package crawler

import (
	"log"
	"sync/atomic"
	"time"
)

type SystemState int

const (
	StateNormal SystemState = iota
	StateElevatedThreat
	StateDeepHibernation
	StateRecovery
)

// HibernationEngine monitors active probe events and transitions the system state to protect OPSEC.
type HibernationEngine struct {
	currentState   atomic.Value
	probeCounter   uint32
	thresholdLimit uint32
	cooldownPeriod time.Duration
}

func NewHibernationEngine(limit uint32, cooldown time.Duration) *HibernationEngine {
	engine := &HibernationEngine{
		thresholdLimit: limit,
		cooldownPeriod: cooldown,
	}
	engine.currentState.Store(StateNormal)
	return engine
}

func (h *HibernationEngine) RegisterProbeEvent() {
	count := atomic.AddUint32(&h.probeCounter, 1)
	if count >= h.thresholdLimit && h.GetState() == StateNormal {
		log.Println("[OPSEC] Active probing detected! Transitioning to DEEP_HIBERNATION...")
		h.currentState.Store(StateDeepHibernation)
		go h.initiateCooldown()
	}
}

func (h *HibernationEngine) initiateCooldown() {
	time.Sleep(h.cooldownPeriod)
	log.Println("[OPSEC] Cooldown period expired. Transitioning to RECOVERY...")
	h.currentState.Store(StateRecovery)
	atomic.StoreUint32(&h.probeCounter, 0)
	
	// Simulate verifying telemetry before full normal mode
	time.Sleep(2 * time.Second)
	log.Println("[OPSEC] Telemetry clean. Resuming NORMAL operations.")
	h.currentState.Store(StateNormal)
}

func (h *HibernationEngine) GetState() SystemState {
	return h.currentState.Load().(SystemState)
}
