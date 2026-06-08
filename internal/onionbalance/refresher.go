/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package onionbalance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/chimbosonic/tor-gateway/internal/tor"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// LabelGateway is the operator-applied label that selects backend Secrets
// (and frontend + backend pods) for a given Gateway.
const LabelGateway = "torgateway.io/gateway"

// LabelRole identifies backend Secrets within a Gateway's set.
const LabelRole = "torgateway.io/role"

// LabelOwnerUID carries the Gateway's metadata.uid so the informer
// LabelSelector and backendsFromSecrets can both reject Secrets that were
// planted by a namespace tenant carrying only the gateway/role labels.
const LabelOwnerUID = "torgateway.io/owner-uid"

// HostnameField is the Secret data key into which each backend's tor-init
// writes its derived .onion; mirrors the Mode A convention for <gw>-keys.
const HostnameField = "hostname"

// RefresherConfig configures a per-Gateway onionbalance refresher.
type RefresherConfig struct {
	GatewayName      string
	GatewayNamespace string
	MasterKeyPath    string        // written into config.yaml services[].key
	ConfigPath       string        // path to write config.yaml
	PIDFile          string        // pidfile of the onionbalance daemon
	Interval         time.Duration // debounce window
	Master           tor.OnionAddress
	// OwnerUID is the Gateway's metadata.uid. It is stamped onto backend Secrets
	// as the torgateway.io/owner-uid label so the informer's LabelSelector and
	// backendsFromSecrets can both reject tenant-planted Secrets that happen to
	// carry the gateway/role labels.
	OwnerUID string
	// Client is the Kubernetes clientset to drive the informer. Production
	// callers pass a real clientset; tests pass a fake (k8s.io/client-go/kubernetes/fake).
	Client kubernetes.Interface
}

// Refresher watches backend Secrets for a Gateway and keeps the
// onionbalance config.yaml + running daemon in sync.
type Refresher struct {
	cfg     RefresherConfig
	mu      sync.Mutex
	pending bool
	timer   *time.Timer
	store   cache.Store // populated in Run
}

// NewRefresher constructs a Refresher. Returns an error if mandatory
// fields are missing.
func NewRefresher(_ context.Context, cfg RefresherConfig) (*Refresher, error) {
	if cfg.GatewayName == "" || cfg.GatewayNamespace == "" {
		return nil, errors.New("onionbalance: GatewayName and GatewayNamespace are required")
	}
	if cfg.ConfigPath == "" || cfg.PIDFile == "" || cfg.MasterKeyPath == "" {
		return nil, errors.New("onionbalance: ConfigPath, PIDFile, MasterKeyPath are required")
	}
	if cfg.Client == nil {
		return nil, errors.New("onionbalance: Client is required")
	}
	if cfg.OwnerUID == "" {
		return nil, errors.New("onionbalance: OwnerUID is required")
	}
	if cfg.Master.String() == "" {
		return nil, errors.New("onionbalance: Master is required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	return &Refresher{cfg: cfg}, nil
}

// Run starts the Secret informer scoped to backend Secrets for the
// configured Gateway and blocks until ctx is cancelled. Every add /
// update / delete event triggers a debounced rewrite of config.yaml and
// a SIGHUP to the onionbalance daemon.
func (r *Refresher) Run(ctx context.Context) error {
	selector := fmt.Sprintf(
		"%s=%s,%s=backend,%s=%s",
		LabelGateway, r.cfg.GatewayName,
		LabelRole,
		LabelOwnerUID, r.cfg.OwnerUID,
	)
	factory := informers.NewSharedInformerFactoryWithOptions(
		r.cfg.Client,
		0,
		informers.WithNamespace(r.cfg.GatewayNamespace),
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.LabelSelector = selector
		}),
	)
	si := factory.Core().V1().Secrets().Informer()
	_, err := si.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { r.schedule() },
		UpdateFunc: func(any, any) { r.schedule() },
		DeleteFunc: func(any) { r.schedule() },
	})
	if err != nil {
		return fmt.Errorf("add event handler: %w", err)
	}
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), si.HasSynced) {
		return fmt.Errorf("onionbalance: informer cache failed to sync")
	}
	r.mu.Lock()
	r.store = si.GetStore()
	r.mu.Unlock()
	// Initial render — pick up whatever Secrets already exist.
	r.rebuild(ctx, si.GetStore().List())
	<-ctx.Done()
	return nil
}

func (r *Refresher) schedule() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.timer != nil {
		r.pending = true
		return
	}
	r.timer = time.AfterFunc(r.cfg.Interval, r.fire)
}

func (r *Refresher) fire() {
	r.mu.Lock()
	r.timer = nil
	pending := r.pending
	r.pending = false
	store := r.store
	r.mu.Unlock()
	if store != nil {
		r.rebuild(context.Background(), store.List())
	}
	if pending {
		r.schedule()
	}
}

// rebuild renders config.yaml from the provided Secret list and SIGHUPs.
// Exposed for tests; production calls go through schedule()→fire().
func (r *Refresher) rebuild(_ context.Context, objs []any) {
	backends := backendsFromSecrets(objs, r.cfg.OwnerUID)
	rendered, err := Render(r.cfg.Master, backends, r.cfg.MasterKeyPath)
	if err != nil {
		slog.Error("onionbalance render failed", "err", err)
		return
	}
	if err := atomicWrite(r.cfg.ConfigPath, []byte(rendered)); err != nil {
		slog.Error("onionbalance write failed", "path", r.cfg.ConfigPath, "err", err)
		return
	}
	if err := sighupPID(r.cfg.PIDFile); err != nil {
		// Not fatal: on first run the daemon may not be up yet.
		slog.Warn("onionbalance SIGHUP failed", "pid", r.cfg.PIDFile, "err", err)
		return
	}
	slog.Info("onionbalance config refreshed", "backends", len(backends))
}

func backendsFromSecrets(objs []any, ownerUID string) []tor.OnionAddress {
	out := make([]tor.OnionAddress, 0, len(objs))
	for _, o := range objs {
		s, ok := o.(*corev1.Secret)
		if !ok {
			continue
		}
		// Label filter: the informer LabelSelector already enforces this at the
		// API-server level; checking here defends against test fakes and future
		// code paths that bypass the informer.
		if s.Labels[LabelOwnerUID] != ownerUID {
			continue
		}
		// OwnerReference check: a tenant with secrets/create could plant a
		// Secret with matching labels. Only trust Secrets whose controller
		// owner matches the Gateway UID.
		ownedByGW := false
		for _, or_ := range s.OwnerReferences {
			if string(or_.UID) == ownerUID && or_.Controller != nil && *or_.Controller {
				ownedByGW = true
				break
			}
		}
		if !ownedByGW {
			continue
		}
		raw, ok := s.Data[HostnameField]
		if !ok || len(raw) == 0 {
			continue
		}
		addr, err := tor.ParseAddress(stringNoSpace(raw))
		if err != nil {
			continue
		}
		out = append(out, addr)
	}
	sortAddrs(out)
	return out
}

func sortAddrs(a []tor.OnionAddress) {
	// in-place insertion sort; len ≤ 8.
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1].String() > a[j].String(); j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}

func stringNoSpace(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			out = append(out, c)
		}
	}
	return string(out)
}

// atomicWrite writes the file via a tmp+rename so half-written files are
// never observed by the daemon.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".obrefresh-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func sighupPID(pidfile string) error {
	raw, err := os.ReadFile(pidfile)
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(stringNoSpace(raw))
	if err != nil {
		return fmt.Errorf("parse pid: %w", err)
	}
	return syscall.Kill(pid, syscall.SIGHUP)
}
