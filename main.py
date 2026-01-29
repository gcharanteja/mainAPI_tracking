from fastapi import FastAPI, Depends, Header, HTTPException, status, Query, Request, UploadFile, File
from fastapi.responses import JSONResponse, FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from database import SessionLocal, engine, Base
import models
import schemas
from datetime import datetime, timedelta
import hashlib
import secrets
import os
import shutil
from typing import List, Dict, Any, Optional
from collections import defaultdict

from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(title="trackingMaster Clone - Phase 3 🔒")

# Allow your frontend origin (or * for testing)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # or ["http://localhost:3000"] for React dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Database ---
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- Helper Functions ---
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def generate_api_key() -> str:
    return secrets.token_hex(32)

def log_audit(db: Session, user_id: int, action: str, resource_type: str, resource_id: int, 
              team_id: Optional[int] = None, project_id: Optional[int] = None, run_id: Optional[int] = None,
              details: Optional[Dict] = None, ip_address: Optional[str] = None):
    """Log an audit event"""
    audit = models.AuditLog(
        user_id=user_id,
        team_id=team_id,
        project_id=project_id,
        run_id=run_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
        ip_address=ip_address
    )
    db.add(audit)
    db.commit()

def verify_api_key(x_api_key: str = Header(...), db: Session = Depends(get_db)):
    """Verify API key and return user"""
    user = db.query(models.User).filter(models.User.api_key == x_api_key).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return user

def check_permission(user: models.User, team_id: int, permission: str, db: Session = Depends(get_db)):
    """Check if user has permission in team"""
    team_member = db.query(models.TeamMember).filter(
        models.TeamMember.user_id == user.id,
        models.TeamMember.team_id == team_id
    ).first()
    
    if not team_member:
        raise HTTPException(status_code=403, detail="User not in team")
    
    # Admin has all permissions
    if team_member.role == "admin":
        return True
    
    # Check custom role
    if team_member.custom_role:
        permissions = team_member.custom_role.permissions
        if not permissions.get(permission, False):
            raise HTTPException(status_code=403, detail=f"Missing permission: {permission}")
        return True
    
    # Fallback for builtin roles
    if team_member.role == "viewer" and permission not in ["view_runs"]:
        raise HTTPException(status_code=403, detail=f"Viewer role cannot {permission}")
    
    return True

# --- Root ---
@app.get("/")
def read_root():
    return {
        "message": "Welcome to trackingMaster Clone 🚀",
        "version": "3.0",
        "features": ["User Auth", "Teams", "Projects", "Runs", "Metrics", "Dashboard", "Audit Logs", "Custom Roles", "SSO/LDAP"]
    }

# --- User Endpoints ---
@app.post("/users/register", response_model=schemas.UserResponse)
def register_user(user_create: schemas.UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(models.User).filter(models.User.email == user_create.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    api_key = generate_api_key()
    new_user = models.User(
        username=user_create.username,
        email=user_create.email,
        password_hash=hash_password(user_create.password),
        api_key=api_key,
        sso_provider=user_create.sso_provider,
        sso_id=user_create.sso_id
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    log_audit(db, new_user.id, "create", "user", new_user.id, details={"email": user_create.email})
    
    return new_user

@app.get("/users/me", response_model=schemas.UserResponse)
def get_current_user(user: models.User = Depends(verify_api_key)):
    return user

# --- Team Endpoints ---
@app.post("/teams", response_model=schemas.TeamResponse)
def create_team(team_create: schemas.TeamCreate, user: models.User = Depends(verify_api_key), 
                db: Session = Depends(get_db), request: Request = None):
    new_team = models.Team(name=team_create.name, description=team_create.description)
    db.add(new_team)
    db.commit()
    db.refresh(new_team)
    
    team_member = models.TeamMember(team_id=new_team.id, user_id=user.id, role="admin")
    db.add(team_member)
    db.commit()
    
    ip = request.client.host if request else None
    log_audit(db, user.id, "create", "team", new_team.id, team_id=new_team.id, 
              details={"name": team_create.name}, ip_address=ip)
    
    return new_team

@app.get("/teams/{team_id}", response_model=schemas.TeamResponse)
def get_team(team_id: int, user: models.User = Depends(verify_api_key), db: Session = Depends(get_db)):
    team = db.query(models.Team).filter(models.Team.id == team_id).first()
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    return team

@app.get("/teams")
def list_teams(user: models.User = Depends(verify_api_key), db: Session = Depends(get_db)):
    teams = db.query(models.Team).join(models.TeamMember).filter(models.TeamMember.user_id == user.id).all()
    return teams

# --- Custom Role Endpoints ---
@app.post("/teams/{team_id}/roles", response_model=schemas.CustomRoleResponse)
def create_custom_role(team_id: int, role_create: schemas.CustomRoleCreate, 
                       user: models.User = Depends(verify_api_key), db: Session = Depends(get_db)):
    """Create custom role in team"""
    check_permission(user, team_id, "manage_roles", db)
    
    new_role = models.CustomRole(
        team_id=team_id,
        name=role_create.name,
        description=role_create.description,
        permissions=role_create.permissions
    )
    db.add(new_role)
    db.commit()
    db.refresh(new_role)
    
    log_audit(db, user.id, "create", "role", new_role.id, team_id=team_id, 
              details={"role_name": role_create.name, "permissions": role_create.permissions})
    
    return new_role

@app.get("/teams/{team_id}/roles")
def list_roles(team_id: int, user: models.User = Depends(verify_api_key), db: Session = Depends(get_db)):
    """List all custom roles in team"""
    roles = db.query(models.CustomRole).filter(models.CustomRole.team_id == team_id).all()
    return roles

@app.post("/teams/{team_id}/members/{user_id}/role/{role_id}")
def assign_role(team_id: int, user_id: int, role_id: int, 
                user: models.User = Depends(verify_api_key), db: Session = Depends(get_db)):
    """Assign custom role to team member"""
    check_permission(user, team_id, "manage_roles", db)
    
    team_member = db.query(models.TeamMember).filter(
        models.TeamMember.team_id == team_id,
        models.TeamMember.user_id == user_id
    ).first()
    
    if not team_member:
        raise HTTPException(status_code=404, detail="Team member not found")
    
    role = db.query(models.CustomRole).filter(models.CustomRole.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    
    team_member.role_id = role_id
    db.commit()
    
    log_audit(db, user.id, "assign", "role", role_id, team_id=team_id,
              details={"assigned_to_user": user_id})
    
    return {"message": f"Role assigned to user {user_id}"}

# --- Project Endpoints ---
@app.post("/teams/{team_id}/projects", response_model=schemas.ProjectResponse)
def create_project(team_id: int, project_create: schemas.ProjectCreate, user: models.User = Depends(verify_api_key), 
                   db: Session = Depends(get_db), request: Request = None):
    check_permission(user, team_id, "manage_team", db)
    
    team = db.query(models.Team).filter(models.Team.id == team_id).first()
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    
    new_project = models.Project(name=project_create.name, team_id=team_id, description=project_create.description)
    db.add(new_project)
    db.commit()
    db.refresh(new_project)
    
    ip = request.client.host if request else None
    log_audit(db, user.id, "create", "project", new_project.id, team_id=team_id, project_id=new_project.id,
              details={"name": project_create.name}, ip_address=ip)
    
    return new_project

@app.get("/teams/{team_id}/projects")
def list_projects(team_id: int, user: models.User = Depends(verify_api_key), db: Session = Depends(get_db)):
    projects = db.query(models.Project).filter(models.Project.team_id == team_id).all()
    return projects

@app.get("/projects/{project_id}", response_model=schemas.ProjectResponse)
def get_project(project_id: int, user: models.User = Depends(verify_api_key), db: Session = Depends(get_db)):
    project = db.query(models.Project).filter(models.Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

# --- Run Endpoints ---
@app.post("/projects/{project_id}/runs/init", response_model=schemas.RunResponse)
def init_run(project_id: int, run_create: schemas.RunCreate, user: models.User = Depends(verify_api_key), 
             db: Session = Depends(get_db), request: Request = None):
    project = db.query(models.Project).filter(models.Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    check_permission(user, project.team_id, "log_metrics", db)
    
    # Convert config dict to JSON string if provided
    config_str = None
    if run_create.config:
        import json
        config_str = json.dumps(run_create.config)
    
    new_run = models.Run(
        user_id=user.id, 
        project_id=project_id, 
        name=run_create.name, 
        config=config_str, 
        status="running",
        # NEW FIELDS
        notes=run_create.notes,
        tags=run_create.tags or [],
        hostname=run_create.hostname,
        os_info=run_create.os_info,
        python_version=run_create.python_version,
        python_executable=run_create.python_executable,
        command=run_create.command,
        cli_version="3.0"  # Your API version
    )
    db.add(new_run)
    db.commit()
    db.refresh(new_run)
    
    ip = request.client.host if request else None
    log_audit(db, user.id, "create", "run", new_run.id, project_id=project_id, run_id=new_run.id,
              details={"run_name": run_create.name, "hostname": run_create.hostname}, ip_address=ip)
    
    return new_run

@app.post("/runs/{run_id}/log")
def log_metric(run_id: int, metric: schemas.MetricLog, user: models.User = Depends(verify_api_key), 
               db: Session = Depends(get_db), request: Request = None):
    run = db.query(models.Run).filter(models.Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    project = db.query(models.Project).filter(models.Project.id == run.project_id).first()
    check_permission(user, project.team_id, "log_metrics", db)
    
    # Convert value to string for storage (supports both numeric and text)
    value_str = str(metric.value)
    
    new_metric = models.RunMetric(run_id=run_id, name=metric.name, value=value_str, step=metric.step)
    db.add(new_metric)
    db.commit()
    db.refresh(new_metric)
    
    run.storage_used_mb += 0.001
    db.commit()
    
    ip = request.client.host if request else None
    log_audit(db, user.id, "log_metric", "metric", new_metric.id, run_id=run_id, project_id=run.project_id,
              details={"metric_name": metric.name, "value": metric.value}, ip_address=ip)
    
    return new_metric

@app.get("/runs/{run_id}", response_model=schemas.RunResponse)
def get_run(run_id: int, user: models.User = Depends(verify_api_key), db: Session = Depends(get_db)):
    run = db.query(models.Run).filter(models.Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run

@app.post("/runs/{run_id}/finish")
def finish_run(run_id: int, user: models.User = Depends(verify_api_key), db: Session = Depends(get_db), request: Request = None):
    run = db.query(models.Run).filter(models.Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    project = db.query(models.Project).filter(models.Project.id == run.project_id).first()
    check_permission(user, project.team_id, "log_metrics", db)
    
    run.status = "finished"
    run.finished_at = datetime.utcnow()
    
    # NEW - Calculate runtime
    if run.created_at:
        runtime = (run.finished_at - run.created_at).total_seconds()
        run.runtime_seconds = runtime
    
    db.commit()
    
    ip = request.client.host if request else None
    log_audit(db, user.id, "finish", "run", run_id, run_id=run_id, project_id=run.project_id, ip_address=ip)
    
    return {
        "message": f"Run {run_id} finished",
        "status": run.status,
        "runtime_seconds": run.runtime_seconds
    }

@app.get("/runs/{run_id}/metrics")
def get_run_metrics(run_id: int, user: models.User = Depends(verify_api_key), db: Session = Depends(get_db)):
    metrics = db.query(models.RunMetric).filter(models.RunMetric.run_id == run_id).all()
    return metrics

# --- File Upload Endpoints ---
@app.post("/runs/{run_id}/upload-file")
async def upload_file(
    run_id: int,
    file: UploadFile = File(...),
    file_type: Optional[str] = Query(None),
    user: models.User = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """Upload a file to a run (config.yaml, requirements.txt, etc.)"""
    run = db.query(models.Run).filter(models.Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    project = db.query(models.Project).filter(models.Project.id == run.project_id).first()
    check_permission(user, project.team_id, "log_metrics", db)
    
    # Create storage directory
    storage_dir = f"./storage/runs/{run_id}"
    os.makedirs(storage_dir, exist_ok=True)
    
    # Save file
    file_path = os.path.join(storage_dir, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    # Get file size
    file_size = os.path.getsize(file_path)
    
    # Create database record
    run_file = models.RunFile(
        run_id=run_id,
        filename=file.filename,
        file_path=file_path,
        file_size_bytes=file_size,
        file_type=file_type
    )
    db.add(run_file)
    
    # Update storage
    run.storage_used_mb += file_size / (1024 * 1024)
    db.commit()
    db.refresh(run_file)
    
    log_audit(db, user.id, "upload_file", "file", run_file.id, run_id=run_id,
              details={"filename": file.filename, "size_bytes": file_size})
    
    return {
        "message": "File uploaded successfully",
        "file_id": run_file.id,
        "filename": file.filename,
        "size_bytes": file_size
    }


@app.get("/runs/{run_id}/files")
def list_run_files(run_id: int, user: models.User = Depends(verify_api_key), db: Session = Depends(get_db)):
    """List all files uploaded to a run"""
    files = db.query(models.RunFile).filter(models.RunFile.run_id == run_id).all()
    return [
        {
            "id": f.id,
            "filename": f.filename,
            "size_bytes": f.file_size_bytes,
            "uploaded_at": f.uploaded_at.isoformat(),
            "file_type": f.file_type
        }
        for f in files
    ]


@app.get("/runs/{run_id}/files/{file_id}/download")
async def download_file(
    run_id: int,
    file_id: int,
    user: models.User = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """Download a file from a run"""
    run_file = db.query(models.RunFile).filter(
        models.RunFile.id == file_id,
        models.RunFile.run_id == run_id
    ).first()
    
    if not run_file:
        raise HTTPException(status_code=404, detail="File not found")
    
    if not os.path.exists(run_file.file_path):
        raise HTTPException(status_code=404, detail="File no longer exists on disk")
    
    return FileResponse(
        path=run_file.file_path,
        filename=run_file.filename,
        media_type="application/octet-stream"
    )

# --- Audit Log Endpoints ---
@app.get("/teams/{team_id}/audit-logs")
def get_team_audit_logs(team_id: int, limit: int = Query(100), user: models.User = Depends(verify_api_key), 
                        db: Session = Depends(get_db)):
    """Get audit logs for a team"""
    check_permission(user, team_id, "manage_team", db)
    
    logs = db.query(models.AuditLog).filter(models.AuditLog.team_id == team_id)\
        .order_by(models.AuditLog.timestamp.desc()).limit(limit).all()
    return logs

@app.get("/projects/{project_id}/audit-logs")
def get_project_audit_logs(project_id: int, limit: int = Query(100), user: models.User = Depends(verify_api_key), 
                           db: Session = Depends(get_db)):
    """Get audit logs for a project"""
    project = db.query(models.Project).filter(models.Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    check_permission(user, project.team_id, "manage_team", db)
    
    logs = db.query(models.AuditLog).filter(models.AuditLog.project_id == project_id)\
        .order_by(models.AuditLog.timestamp.desc()).limit(limit).all()
    return logs

@app.get("/audit-logs")
def get_all_audit_logs(limit: int = Query(100), user: models.User = Depends(verify_api_key), 
                       db: Session = Depends(get_db)):
    """Get audit logs for current user"""
    logs = db.query(models.AuditLog).filter(models.AuditLog.user_id == user.id)\
        .order_by(models.AuditLog.timestamp.desc()).limit(limit).all()
    return logs

# --- Dashboard Endpoints ---
@app.get("/dashboard/overview")
def get_dashboard_overview(user: models.User = Depends(verify_api_key), db: Session = Depends(get_db)):
    teams_count = db.query(models.Team).join(models.TeamMember).filter(models.TeamMember.user_id == user.id).count()
    projects_count = db.query(models.Project).join(models.Team).join(models.TeamMember).filter(models.TeamMember.user_id == user.id).count()
    runs_count = db.query(models.Run).filter(models.Run.user_id == user.id).count()
    finished_runs = db.query(models.Run).filter(models.Run.user_id == user.id, models.Run.status == "finished").count()
    total_metrics = db.query(func.count(models.RunMetric.id)).scalar()
    total_storage_mb = db.query(func.sum(models.Run.storage_used_mb)).scalar() or 0
    total_storage_gb = total_storage_mb / 1024
    
    return {
        "user": user.username,
        "stats": {
            "teams": teams_count,
            "projects": projects_count,
            "runs": runs_count,
            "finished_runs": finished_runs,
            "total_metrics": total_metrics,
            "total_storage_gb": round(total_storage_gb, 2)
        }
    }

@app.get("/projects/{project_id}/dashboard")
def get_project_dashboard(project_id: int, user: models.User = Depends(verify_api_key), db: Session = Depends(get_db)):
    project = db.query(models.Project).filter(models.Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    runs = db.query(models.Run).filter(models.Run.project_id == project_id).all()
    
    run_stats = {
        "total": len(runs),
        "running": len([r for r in runs if r.status == "running"]),
        "finished": len([r for r in runs if r.status == "finished"]),
        "failed": len([r for r in runs if r.status == "failed"])
    }
    
    recent_runs = db.query(models.Run).filter(models.Run.project_id == project_id).order_by(models.Run.created_at.desc()).limit(5).all()
    recent_runs_data = [
        {
            "id": r.id,
            "name": r.name,
            "status": r.status,
            "created_at": r.created_at.isoformat(),
            "finished_at": r.finished_at.isoformat() if r.finished_at else None
        }
        for r in recent_runs
    ]
    
    project_storage_mb = db.query(func.sum(models.Run.storage_used_mb)).filter(models.Run.project_id == project_id).scalar() or 0
    project_storage_gb = project_storage_mb / 1024
    
    return {
        "project_id": project_id,
        "project_name": project.name,
        "run_stats": run_stats,
        "recent_runs": recent_runs_data,
        "storage_gb": round(project_storage_gb, 2)
    }

@app.get("/projects/{project_id}/runs/compare")
def compare_runs(
    project_id: int,
    run_ids: str = Query(..., description="Comma-separated run IDs"),
    user: models.User = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    run_id_list = [int(x.strip()) for x in run_ids.split(",")]
    runs = db.query(models.Run).filter(models.Run.project_id == project_id, models.Run.id.in_(run_id_list)).all()
    
    if not runs:
        raise HTTPException(status_code=404, detail="No runs found")
    
    comparison_data = []
    for run in runs:
        metrics = db.query(models.RunMetric).filter(models.RunMetric.run_id == run.id).all()
        metrics_dict = defaultdict(list)
        for metric in metrics:
            metrics_dict[metric.name].append({
                "step": metric.step,
                "value": metric.value,
                "logged_at": metric.logged_at.isoformat()
            })
        
        comparison_data.append({
            "run_id": run.id,
            "run_name": run.name,
            "status": run.status,
            "created_at": run.created_at.isoformat(),
            "metrics": dict(metrics_dict)
        })
    
    return {
        "project_id": project_id,
        "runs_compared": len(comparison_data),
        "runs": comparison_data
    }

@app.get("/runs/{run_id}/metrics/aggregated")
def get_aggregated_metrics(run_id: int, user: models.User = Depends(verify_api_key), db: Session = Depends(get_db)):
    run = db.query(models.Run).filter(models.Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    metrics = db.query(models.RunMetric).filter(models.RunMetric.run_id == run_id).all()
    aggregated = defaultdict(lambda: {
        "type": None,
        "min": None,
        "max": None,
        "avg": None,
        "latest": None,
        "count": 0,
        "history": []
    })
    
    for metric in metrics:
        name = metric.name
        value = metric.value
        
        # Try to convert to float for numeric metrics
        try:
            numeric_value = float(value)
            is_numeric = True
        except (ValueError, TypeError):
            numeric_value = None
            is_numeric = False
        
        # Initialize type on first metric for this name
        if aggregated[name]["type"] is None:
            aggregated[name]["type"] = "numeric" if is_numeric else "text"
        
        aggregated[name]["latest"] = value
        aggregated[name]["count"] += 1
        aggregated[name]["history"].append({
            "step": metric.step,
            "value": value,
            "logged_at": metric.logged_at.isoformat()
        })
        
        # Only aggregate numeric values
        if is_numeric:
            if aggregated[name]["min"] is None or numeric_value < aggregated[name]["min"]:
                aggregated[name]["min"] = numeric_value
            if aggregated[name]["max"] is None or numeric_value > aggregated[name]["max"]:
                aggregated[name]["max"] = numeric_value
    
    # Calculate averages for numeric metrics
    for name in aggregated:
        if aggregated[name]["type"] == "numeric":
            numeric_values = []
            for m in aggregated[name]["history"]:
                try:
                    numeric_values.append(float(m["value"]))
                except (ValueError, TypeError):
                    pass
            
            if numeric_values:
                aggregated[name]["avg"] = round(sum(numeric_values) / len(numeric_values), 4)
                aggregated[name]["min"] = round(aggregated[name]["min"], 4) if aggregated[name]["min"] is not None else None
                aggregated[name]["max"] = round(aggregated[name]["max"], 4) if aggregated[name]["max"] is not None else None
    
    return {
        "run_id": run_id,
        "metrics": dict(aggregated)
    }
    return {
        "run_id": run_id,
        "metrics": dict(aggregated)
    }

@app.get("/runs/{run_id}/metrics/query")
def query_metrics(
    run_id: int,
    metric_name: Optional[str] = Query(None),
    min_value: Optional[float] = Query(None),
    max_value: Optional[float] = Query(None),
    min_step: Optional[int] = Query(None),
    max_step: Optional[int] = Query(None),
    user: models.User = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    query = db.query(models.RunMetric).filter(models.RunMetric.run_id == run_id)
    
    if metric_name:
        query = query.filter(models.RunMetric.name == metric_name)
    if min_value is not None:
        query = query.filter(models.RunMetric.value >= min_value)
    if max_value is not None:
        query = query.filter(models.RunMetric.value <= max_value)
    if min_step is not None:
        query = query.filter(models.RunMetric.step >= min_step)
    if max_step is not None:
        query = query.filter(models.RunMetric.step <= max_step)
    
    metrics = query.all()
    
    return {
        "run_id": run_id,
        "filters": {
            "metric_name": metric_name,
            "min_value": min_value,
            "max_value": max_value,
            "min_step": min_step,
            "max_step": max_step
        },
        "results_count": len(metrics),
        "metrics": [
            {
                "name": m.name,
                "value": m.value,
                "step": m.step,
                "logged_at": m.logged_at.isoformat()
            }
            for m in metrics
        ]
    }

@app.get("/runs/{run_id}/visualizations/timeseries")
def get_timeseries_visualization(
    run_id: int,
    metric_name: str = Query(...),
    user: models.User = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    metrics = db.query(models.RunMetric).filter(
        models.RunMetric.run_id == run_id,
        models.RunMetric.name == metric_name
    ).order_by(models.RunMetric.step.asc()).all()
    
    if not metrics:
        raise HTTPException(status_code=404, detail="No metrics found for this metric name")
    
    data = {
        "metric_name": metric_name,
        "x": [m.step for m in metrics],
        "y": [m.value for m in metrics],
        "timestamps": [m.logged_at.isoformat() for m in metrics]
    }
    
    return {
        "run_id": run_id,
        "type": "line_chart",
        "data": data
    }

@app.get("/runs/{run_id}/visualizations/multiplot")
def get_multiplot_visualization(
    run_id: int,
    user: models.User = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    run = db.query(models.Run).filter(models.Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    metrics = db.query(models.RunMetric).filter(models.RunMetric.run_id == run_id).all()
    metrics_by_name = defaultdict(list)
    for metric in metrics:
        metrics_by_name[metric.name].append(metric)
    
    plots = []
    for metric_name, metric_list in metrics_by_name.items():
        plots.append({
            "metric_name": metric_name,
            "x": [m.step for m in sorted(metric_list, key=lambda x: x.step)],
            "y": [m.value for m in sorted(metric_list, key=lambda x: x.step)],
            "min": round(min([m.value for m in metric_list]), 4),
            "max": round(max([m.value for m in metric_list]), 4),
            "avg": round(sum([m.value for m in metric_list]) / len(metric_list), 4)
        })
    
    return {
        "run_id": run_id,
        "run_name": run.name,
        "type": "multi_line_chart",
        "plots": plots
    }

@app.get("/projects/{project_id}/metrics/summary")
def get_project_metrics_summary(
    project_id: int,
    user: models.User = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    project = db.query(models.Project).filter(models.Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    runs = db.query(models.Run).filter(models.Run.project_id == project_id).all()
    all_metrics = defaultdict(list)
    
    for run in runs:
        metrics = db.query(models.RunMetric).filter(models.RunMetric.run_id == run.id).all()
        for metric in metrics:
            all_metrics[metric.name].append(metric.value)
    
    summary = {}
    for metric_name, values in all_metrics.items():
        summary[metric_name] = {
            "min": round(min(values), 4),
            "max": round(max(values), 4),
            "avg": round(sum(values) / len(values), 4),
            "count": len(values),
            "runs_with_metric": len(set([v for m in db.query(models.RunMetric).filter(models.RunMetric.name == metric_name).all() for v in [m.run_id]]))
        }
    
    return {
        "project_id": project_id,
        "project_name": project.name,
        "total_runs": len(runs),
        "metrics_summary": summary
    }

# --- Health Check ---
@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}



import uvicorn

def main():
    # Run the FastAPI app with uvicorn
    uvicorn.run(
        "main:app",          # points to app inside main.py
        host="0.0.0.0",      # listen on all interfaces
        port=8000,           # change this number if you want a different port
        reload=True          # auto-reload on code changes (dev mode)
    )

if __name__ == "__main__":
    main()