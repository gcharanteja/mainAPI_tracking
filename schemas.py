from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List, Dict, Any, Union

# --- User Schemas ---
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    sso_provider: Optional[str] = None
    sso_id: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    api_key: str
    created_at: datetime
    is_active: bool
    sso_provider: Optional[str]

    class Config:
        from_attributes = True

# --- Team Schemas ---
class TeamCreate(BaseModel):
    name: str
    description: Optional[str] = None

class TeamResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    created_at: datetime
    storage_limit_gb: float

    class Config:
        from_attributes = True

# --- Project Schemas ---
class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None

class ProjectResponse(BaseModel):
    id: int
    name: str
    team_id: int
    description: Optional[str]
    created_at: datetime
    storage_used_gb: float

    class Config:
        from_attributes = True

# --- Run Schemas ---
class RunCreate(BaseModel):
    name: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    notes: Optional[str] = None  # NEW
    tags: Optional[List[str]] = []  # NEW
    hostname: Optional[str] = None  # NEW
    os_info: Optional[str] = None  # NEW
    python_version: Optional[str] = None  # NEW
    python_executable: Optional[str] = None  # NEW
    command: Optional[str] = None  # NEW

class RunResponse(BaseModel):
    id: int
    user_id: int
    project_id: int
    name: Optional[str]
    config: Optional[str]
    status: str
    created_at: datetime
    finished_at: Optional[datetime]  # NEW
    storage_used_mb: float
    
    # NEW FIELDS
    notes: Optional[str]
    tags: Optional[List[str]]
    hostname: Optional[str]
    os_info: Optional[str]
    python_version: Optional[str]
    python_executable: Optional[str]
    command: Optional[str]
    cli_version: Optional[str]
    runtime_seconds: Optional[float]

    class Config:
        from_attributes = True

# NEW - File upload schema
class RunFileUpload(BaseModel):
    filename: str
    file_type: Optional[str] = None  # "config", "code", "requirements"


class RunFileResponse(BaseModel):
    id: int
    run_id: int
    filename: str
    file_size_bytes: int
    uploaded_at: datetime
    file_type: Optional[str]

    class Config:
        from_attributes = True

# --- Metric Schemas ---
class MetricLog(BaseModel):
    name: str
    value: Union[float, str]   # <-- allow both numbers and text

    step: Optional[int] = 0

class MetricResponse(BaseModel):
    id: int
    run_id: int
    name: str
    value: Union[float, str]   # <-- same change here

    step: int
    logged_at: datetime

    class Config:
        from_attributes = True

# --- Custom Role Schemas ---
class PermissionSet(BaseModel):
    view_runs: bool = True
    edit_config: bool = False
    log_metrics: bool = True
    delete_runs: bool = False
    manage_team: bool = False
    manage_roles: bool = False

class CustomRoleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    permissions: Dict[str, bool]

class CustomRoleResponse(BaseModel):
    id: int
    team_id: int
    name: str
    description: Optional[str]
    permissions: Dict[str, bool]
    created_at: datetime

    class Config:
        from_attributes = True

# --- Audit Log Schemas ---
class AuditLogCreate(BaseModel):
    action: str
    resource_type: str
    resource_id: int
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None

class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int]
    team_id: Optional[int]
    project_id: Optional[int]
    run_id: Optional[int]
    action: str
    resource_type: str
    resource_id: int
    details: Dict[str, Any]
    ip_address: Optional[str]
    timestamp: datetime

    class Config:
        from_attributes = True

# --- Dashboard Schemas ---
class DashboardOverview(BaseModel):
    user: str
    stats: Dict[str, Any]

class ProjectDashboard(BaseModel):
    project_id: int
    project_name: str
    run_stats: Dict[str, int]
    recent_runs: List[Dict[str, Any]]
    storage_gb: float

class AggregatedMetrics(BaseModel):
    run_id: int
    metrics: Dict[str, Any]

class VisualizationData(BaseModel):
    run_id: int
    type: str
    data: Dict[str, Any]