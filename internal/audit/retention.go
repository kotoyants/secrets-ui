package audit

import (
	"context"
	"log/slog"
	"time"
)

// Pruner deletes persisted events older than a cutoff (implemented by store.Store).
type Pruner interface {
	DeleteAuditEventsBefore(ctx context.Context, ts time.Time) (int64, error)
}

// RunRetention deletes persisted events older than retention now and then every
// interval, until ctx is done. It keeps no state, so running it in every replica
// is safe (deletes are idempotent). retention <= 0 disables pruning.
func RunRetention(ctx context.Context, p Pruner, retention, interval time.Duration, log *slog.Logger) {
	if retention <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		n, err := p.DeleteAuditEventsBefore(ctx, time.Now().Add(-retention))
		switch {
		case err != nil && ctx.Err() == nil:
			log.ErrorContext(ctx, "prune audit events", "err", err)
		case n > 0:
			log.InfoContext(ctx, "pruned audit events", "deleted", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
