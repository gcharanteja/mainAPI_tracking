from typing import Dict, Any, Optional, List

class Run:
    """Represents an experiment run"""
    
    def __init__(self, client, run_data: Dict[str, Any]):
        """
        Initialize Run instance
        
        Args:
            client: TrackingClient instance
            run_data: Run data from API
        """
        self.client = client
        self.id = run_data.get("id")
        self.name = run_data.get("name")
        self.status = run_data.get("status")
        self.project_id = run_data.get("project_id")
        self.created_at = run_data.get("created_at")
        self.finished_at = run_data.get("finished_at")
        self.config = run_data.get("config", {})
        self.storage_used_mb = run_data.get("storage_used_mb", 0)
        
        # 🆕 NEW FIELDS
        self.notes = run_data.get("notes")
        self.tags = run_data.get("tags", [])
        self.hostname = run_data.get("hostname")
        self.os_info = run_data.get("os_info")
        self.python_version = run_data.get("python_version")
        self.python_executable = run_data.get("python_executable")
        self.command = run_data.get("command")
        self.cli_version = run_data.get("cli_version")
        self.runtime_seconds = run_data.get("runtime_seconds")
        
        self._raw_data = run_data
    
    def log_metric(self, name: str, value: float, step: int = 0) -> Dict[str, Any]:
        """
        Log a metric to this run
        
        Args:
            name: Metric name
            value: Metric value
            step: Training step
            
        Returns:
            Logged metric data
        """
        return self.client.log_metric(self.id, name, value, step)
    
    def log_message(self, message: str, step: int = 0) -> Dict[str, Any]:
        """
        Log a console message/output to this run
        
        Args:
            message: Console output text
            step: Training step
            
        Returns:
            Logged message data
        """
        return self.client.log_message(self.id, message, step)
    
    def finish(self) -> Dict[str, Any]:
        """
        Finish this run and calculate runtime
        
        Returns:
            Run finish response with runtime_seconds
        """
        response = self.client.finish_run(self.id)
        self.status = "finished"
        self.runtime_seconds = response.get("runtime_seconds")
        return response
    
    def get_metrics(self) -> List[Dict[str, Any]]:
        """
        Get all metrics for this run
        
        Returns:
            List of metrics
        """
        return self.client.get_run_metrics(self.id)
    
    def get_aggregated_metrics(self) -> Dict[str, Any]:
        """
        Get aggregated metrics for this run
        
        Returns:
            Aggregated metrics data
        """
        return self.client.get_aggregated_metrics(self.id)
    
    def query_metrics(self, metric_name: Optional[str] = None,
                     min_value: Optional[float] = None, max_value: Optional[float] = None,
                     min_step: Optional[int] = None, max_step: Optional[int] = None) -> Dict[str, Any]:
        """
        Query metrics with filters
        
        Args:
            metric_name: Filter by metric name
            min_value: Minimum metric value
            max_value: Maximum metric value
            min_step: Minimum step
            max_step: Maximum step
            
        Returns:
            Query results
        """
        return self.client.query_metrics(self.id, metric_name, min_value, max_value, min_step, max_step)
    
    def get_timeseries_visualization(self, metric_name: str) -> Dict[str, Any]:
        """
        Get timeseries visualization for a metric
        
        Args:
            metric_name: Metric name to visualize
            
        Returns:
            Visualization data
        """
        return self.client.get_timeseries_visualization(self.id, metric_name)
    
    def get_multiplot_visualization(self) -> Dict[str, Any]:
        """
        Get multiplot visualization for all metrics
        
        Returns:
            Visualization data
        """
        return self.client.get_multiplot_visualization(self.id)
    
    # 🆕 NEW - File Upload Methods
    def upload_file(self, file_path: str, file_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Upload a file to this run
        
        Args:
            file_path: Local path to file
            file_type: Type of file (config, code, requirements, model, other)
            
        Returns:
            Upload response with file_id
        """
        return self.client.upload_file(self.id, file_path, file_type)
    
    def list_files(self) -> List[Dict[str, Any]]:
        """
        List all files uploaded to this run
        
        Returns:
            List of file metadata
        """
        return self.client.list_run_files(self.id)
    
    def download_file(self, file_id: int, output_path: str) -> None:
        """
        Download a file from this run
        
        Args:
            file_id: File ID
            output_path: Local path to save file
        """
        return self.client.download_file(self.id, file_id, output_path)
    
    def refresh(self) -> None:
        """Refresh run data from server"""
        updated_run = self.client.get_run(self.id)
        self.__dict__.update(updated_run.__dict__)
    
    def __repr__(self) -> str:
        return f"Run(id={self.id}, name='{self.name}', status='{self.status}', runtime={self.runtime_seconds}s)"
    
    def __str__(self) -> str:
        runtime_str = f" ({self.runtime_seconds:.1f}s)" if self.runtime_seconds else ""
        return f"Run {self.id}: {self.name} ({self.status}){runtime_str}"