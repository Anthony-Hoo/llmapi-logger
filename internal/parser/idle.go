package parser

import "context"

// IdleTask is optional bounded work run on the parser goroutine at the scan
// cadence, after the insights backfill, and only while the live queue is
// empty. It must return quickly: long work belongs in a goroutine the task
// guards itself. A panic is recovered and dropped.
type IdleTask func(context.Context)

// AddIdleTask registers an idle task. Call it before Start.
func (worker *Worker) AddIdleTask(task IdleTask) {
	if worker == nil || task == nil {
		return
	}
	worker.mu.Lock()
	worker.idleTasks = append(worker.idleTasks, task)
	worker.mu.Unlock()
}

// HasIdleTasks reports whether any idle task is registered.
func (worker *Worker) HasIdleTasks() bool {
	if worker == nil {
		return false
	}
	worker.mu.Lock()
	defer worker.mu.Unlock()
	return len(worker.idleTasks) > 0
}

func (worker *Worker) runIdleTasks(ctx context.Context) {
	worker.mu.Lock()
	tasks := append([]IdleTask(nil), worker.idleTasks...)
	worker.mu.Unlock()
	for _, task := range tasks {
		if ctx.Err() != nil || len(worker.queue) > 0 {
			return
		}
		func() {
			defer func() {
				if recover() != nil {
					worker.logger.Warn("parser idle task failed", "error_code", "idle_task_panic")
				}
			}()
			task(ctx)
		}()
	}
}
