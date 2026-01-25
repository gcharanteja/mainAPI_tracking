import requests
from typing import Optional, Dict, Any, List
from .run import Run

class TrackingClient:
    """SDK Client for trackingMaster API"""
    
    def __init__(self, api_key: str, base_url: str = "http://localhost:8000"):
        """
        Initialize TrackingClient
        
        Args:
            api_key: API key for authentication
            base_url: Base URL of trackingMaster server
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.headers = {"X-API-Key": self.api_key}
    
    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make HTTP request to API"""
        url = f"{self.base_url}{endpoint}"
        headers = self.headers.copy()
        headers.update(kwargs.pop("headers", {}))
        
        response = requests.request(method, url, headers=headers, **kwargs)
        response.raise_for_status()
        return response.json()
    
    # --- User Methods ---
    def get_current_user(self) -> Dict[str, Any]:
        """Get current authenticated user"""
        return self._request("GET", "/users/me")
    
    # --- Team Methods ---
    def create_team(self, name: str, description: str = "") -> Dict[str, Any]:
        """Create a new team"""
        data = {"name": name, "description": description}
        return self._request("POST", "/teams", json=data)
    
    def get_team(self, team_id: int) -> Dict[str, Any]:
        """Get team by ID"""
        return self._request("GET", f"/teams/{team_id}")
    
    def list_teams(self) -> List[Dict[str, Any]]:
        """List all user teams"""
        return self._request("GET", "/teams")
    
    # --- Project Methods ---
    def create_project(self, team_id: int, name: str, description: str = "") -> Dict[str, Any]:
        """Create a new project in a team"""
        data = {"name": name, "description": description}
        return self._request("POST", f"/teams/{team_id}/projects", json=data)
    
    def get_project(self, project_id: int) -> Dict[str, Any]:
        """Get project by ID"""
        return self._request("GET", f"/projects/{project_id}")
    
    def list_projects(self, team_id: int) -> List[Dict[str, Any]]:
        """List all projects in a team"""
        return self._request("GET", f"/teams/{team_id}/projects")
    
    # --- Run Methods ---
    def init_run(self, project_id: int, name: str, config: Dict[str, Any] = None) -> Run:
        """Initialize a new experiment run"""
        data = {"name": name, "config": config or {}}
        response = self._request("POST", f"/projects/{project_id}/runs/init", json=data)
        return Run(client=self, run_data=response)
    
    def get_run(self, run_id: int) -> Run:
        """Get run by ID"""
        response = self._request("GET", f"/runs/{run_id}")
        return Run(client=self, run_data=response)
    
    def finish_run(self, run_id: int) -> Dict[str, Any]:
        """Finish a run"""
        return self._request("POST", f"/runs/{run_id}/finish")
    
    # --- Metric Methods ---
    def log_metric(self, run_id: int, name: str, value: float, step: int = 0) -> Dict[str, Any]:
        """Log a metric to a run"""
        data = {"name": name, "value": value, "step": step}
        return self._request("POST", f"/runs/{run_id}/log", json=data)
    
    def log_message(self, run_id: int, message: str, step: int = 0) -> Dict[str, Any]:
        """Log a console message/output to a run"""
        data = {"name": "console_output", "value": message, "step": step}
        return self._request("POST", f"/runs/{run_id}/log", json=data)
    
    def get_run_metrics(self, run_id: int) -> List[Dict[str, Any]]:
        """Get all metrics for a run"""
        return self._request("GET", f"/runs/{run_id}/metrics")
    
    def get_aggregated_metrics(self, run_id: int) -> Dict[str, Any]:
        """Get aggregated metrics for a run"""
        return self._request("GET", f"/runs/{run_id}/metrics/aggregated")
    
    def query_metrics(self, run_id: int, metric_name: Optional[str] = None,
                     min_value: Optional[float] = None, max_value: Optional[float] = None,
                     min_step: Optional[int] = None, max_step: Optional[int] = None) -> Dict[str, Any]:
        """Query metrics with filters"""
        params = {
            "metric_name": metric_name,
            "min_value": min_value,
            "max_value": max_value,
            "min_step": min_step,
            "max_step": max_step,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._request("GET", f"/runs/{run_id}/metrics/query", params=params)
    
    # --- Dashboard Methods ---
    def get_dashboard_overview(self) -> Dict[str, Any]:
        """Get user dashboard overview"""
        return self._request("GET", "/dashboard/overview")
    
    def get_project_dashboard(self, project_id: int) -> Dict[str, Any]:
        """Get project dashboard"""
        return self._request("GET", f"/projects/{project_id}/dashboard")
    
    def compare_runs(self, project_id: int, run_ids: List[int]) -> Dict[str, Any]:
        """Compare multiple runs"""
        run_ids_str = ",".join(map(str, run_ids))
        return self._request("GET", f"/projects/{project_id}/runs/compare", 
                           params={"run_ids": run_ids_str})
    
    # --- Visualization Methods ---
    def get_timeseries_visualization(self, run_id: int, metric_name: str) -> Dict[str, Any]:
        """Get timeseries visualization for a metric"""
        return self._request("GET", f"/runs/{run_id}/visualizations/timeseries",
                           params={"metric_name": metric_name})
    
    def get_multiplot_visualization(self, run_id: int) -> Dict[str, Any]:
        """Get multiplot visualization for all metrics"""
        return self._request("GET", f"/runs/{run_id}/visualizations/multiplot")
    
    # --- Audit Log Methods ---
    def get_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get user audit logs"""
        return self._request("GET", "/audit-logs", params={"limit": limit})
    
    def get_team_audit_logs(self, team_id: int, limit: int = 100) -> List[Dict[str, Any]]:
        """Get team audit logs"""
        return self._request("GET", f"/teams/{team_id}/audit-logs", params={"limit": limit})
    
    def get_project_audit_logs(self, project_id: int, limit: int = 100) -> List[Dict[str, Any]]:
        """Get project audit logs"""
        return self._request("GET", f"/projects/{project_id}/audit-logs", params={"limit": limit})
    
    # --- Role Methods ---
    def create_custom_role(self, team_id: int, name: str, description: str, 
                          permissions: Dict[str, bool]) -> Dict[str, Any]:
        """Create custom role in team"""
        data = {"name": name, "description": description, "permissions": permissions}
        return self._request("POST", f"/teams/{team_id}/roles", json=data)
    
    def list_roles(self, team_id: int) -> List[Dict[str, Any]]:
        """List all roles in team"""
        return self._request("GET", f"/teams/{team_id}/roles")
    
    def assign_role(self, team_id: int, user_id: int, role_id: int) -> Dict[str, Any]:
        """Assign role to team member"""
        return self._request("POST", f"/teams/{team_id}/members/{user_id}/role/{role_id}")
    
    # --- Health Check ---
    def health_check(self) -> Dict[str, Any]:
        """Check API health"""
        return self._request("GET", "/health")