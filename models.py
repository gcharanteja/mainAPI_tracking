from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime, Boolean, Text, JSON
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime

# --- User & Team Models ---
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    api_key = Column(String, unique=True, index=True)
    password_hash = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # SSO/LDAP fields
    sso_provider = Column(String, nullable=True)  # google, github, ldap
    sso_id = Column(String, nullable=True)
    
    teams = relationship("TeamMember", back_populates="user")
    runs = relationship("Run", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")

class Team(Base):
    __tablename__ = "teams"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    storage_limit_gb = Column(Float, default=5.0)  # Free tier: 5GB
    
    members = relationship("TeamMember", back_populates="team")
    projects = relationship("Project", back_populates="team")
    roles = relationship("CustomRole", back_populates="team")
    audit_logs = relationship("AuditLog", back_populates="team")

class TeamMember(Base):
    __tablename__ = "team_members"

    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(Integer, ForeignKey("teams.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    role_id = Column(Integer, ForeignKey("custom_roles.id"), nullable=True)
    role = Column(String, default="member")  # Fallback for builtin roles: admin, member, viewer
    joined_at = Column(DateTime, default=datetime.utcnow)
    
    team = relationship("Team", back_populates="members")
    user = relationship("User", back_populates="teams")
    custom_role = relationship("CustomRole", back_populates="members")

# --- Custom Roles & Permissions ---
class CustomRole(Base):
    __tablename__ = "custom_roles"

    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(Integer, ForeignKey("teams.id"))
    name = Column(String)
    description = Column(String, nullable=True)
    permissions = Column(JSON, default={})  # e.g., {"view_runs": true, "edit_config": false}
    created_at = Column(DateTime, default=datetime.utcnow)
    
    team = relationship("Team", back_populates="roles")
    members = relationship("TeamMember", back_populates="custom_role")

# --- Project & Run Models ---
class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    team_id = Column(Integer, ForeignKey("teams.id"))
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    storage_used_gb = Column(Float, default=0.0)
    
    team = relationship("Team", back_populates="projects")
    runs = relationship("Run", back_populates="project")
    audit_logs = relationship("AuditLog", back_populates="project")

class Run(Base):
    __tablename__ = "runs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    project_id = Column(Integer, ForeignKey("projects.id"))
    name = Column(String, nullable=True)
    config = Column(Text, nullable=True)
    status = Column(String, default="running")  # running, finished, failed
    created_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    storage_used_mb = Column(Float, default=0.0)
    
    user = relationship("User", back_populates="runs")
    project = relationship("Project", back_populates="runs")
    metrics = relationship("RunMetric", back_populates="run")
    audit_logs = relationship("AuditLog", back_populates="run")

class RunMetric(Base):
    __tablename__ = "run_metrics"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"))
    name = Column(String)
    value = Column(Text)  # Changed from Float to Text to support both numeric and string values
    step = Column(Integer, default=0)
    logged_at = Column(DateTime, default=datetime.utcnow)
    
    run = relationship("Run", back_populates="metrics")

# --- Audit Logging ---
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    team_id = Column(Integer, ForeignKey("teams.id"), nullable=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True)
    
    action = Column(String)  # create, update, delete, log_metric, finish_run
    resource_type = Column(String)  # user, team, project, run, metric
    resource_id = Column(Integer)
    details = Column(JSON, default={})  # Extra context
    ip_address = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    user = relationship("User", back_populates="audit_logs")
    team = relationship("Team", back_populates="audit_logs")
    project = relationship("Project", back_populates="audit_logs")
    run = relationship("Run", back_populates="audit_logs")

# --- Legacy Models ---
class Experiment(Base):
    __tablename__ = "experiments"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String)

    metrics = relationship("Metric", back_populates="experiment")

class Metric(Base):
    __tablename__ = "metrics"

    id = Column(Integer, primary_key=True, index=True)
    experiment_id = Column(Integer, ForeignKey("experiments.id"))
    name = Column(String)
    value = Column(Float)

    experiment = relationship("Experiment", back_populates="metrics")