from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from database import SessionLocal
import models
from typing import Optional

def cleanup_stale_runs(timeout_hours: int = 24):
    """
    Mark runs as 'failed' if no activity for X hours
    Runs automatically every hour
    """
    db = SessionLocal()
    try:
        cutoff_time = datetime.utcnow() - timedelta(hours=timeout_hours)
        
        # Find all running runs that haven't been updated
        stale_runs = db.query(models.Run).filter(
            models.Run.status == "running",
            models.Run.created_at < cutoff_time
        ).all()
        
        for run in stale_runs:
            # Mark as failed
            run.status = "failed"
            run.finished_at = datetime.utcnow()
            
            # Calculate runtime
            if run.created_at:
                runtime = (run.finished_at - run.created_at).total_seconds()
                run.runtime_seconds = runtime
            
            # Log audit
            audit = models.AuditLog(
                user_id=run.user_id,
                project_id=run.project_id,
                run_id=run.id,
                action="auto_fail",
                resource_type="run",
                resource_id=run.id,
                details={
                    "reason": "stale_run_timeout",
                    "timeout_hours": timeout_hours,
                    "created_at": run.created_at.isoformat()
                }
            )
            db.add(audit)
        
        db.commit()
        
        if stale_runs:
            print(f"[CLEANUP] Marked {len(stale_runs)} stale runs as failed")
            print(f"[CLEANUP] Run IDs: {[r.id for r in stale_runs]}")
        
        return len(stale_runs)
        
    except Exception as e:
        print(f"[CLEANUP ERROR] {e}")
        db.rollback()
        return 0
    finally:
        db.close()


def cleanup_old_audit_logs(days_to_keep: int = 90):
    """
    Delete audit logs older than X days
    Runs automatically once per day
    """
    db = SessionLocal()
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        
        deleted_count = db.query(models.AuditLog).filter(
            models.AuditLog.timestamp < cutoff_date
        ).delete()
        
        db.commit()
        
        if deleted_count > 0:
            print(f"[CLEANUP] Deleted {deleted_count} old audit logs (>{days_to_keep} days)")
        
        return deleted_count
        
    except Exception as e:
        print(f"[CLEANUP ERROR] {e}")
        db.rollback()
        return 0
    finally:
        db.close()