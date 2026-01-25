import pytest
from unittest.mock import Mock, patch, MagicMock
from pck67_pkg import TrackingClient, Run


@pytest.fixture
def client():
    """Create test client"""
    return TrackingClient(api_key="test-api-key", base_url="http://13.64.248.226:8000")


@pytest.fixture
def mock_run_data():
    """Sample run data"""
    return {
        "id": 1,
        "name": "test_run",
        "status": "running",
        "project_id": 1,
        "created_at": "2026-01-08T10:00:00",
        "finished_at": None,
        "config": {"lr": 0.001},
        "storage_used_mb": 0.5
    }


class TestTrackingClient:
    
    @patch('pck67_pkg.client.requests.request')
    def test_get_current_user(self, mock_request, client):
        """Test getting current user"""
        mock_response = Mock()
        mock_response.json.return_value = {"id": 1, "username": "testuser", "email": "test@example.com"}
        mock_request.return_value = mock_response
        
        result = client.get_current_user()
        
        assert result["username"] == "testuser"
        mock_request.assert_called_once()
    
    @patch('pck67_pkg.client.requests.request')
    def test_create_team(self, mock_request, client):
        """Test creating team"""
        mock_response = Mock()
        mock_response.json.return_value = {"id": 1, "name": "test_team", "description": "Test"}
        mock_request.return_value = mock_response
        
        result = client.create_team("test_team", "Test")
        
        assert result["name"] == "test_team"
        mock_request.assert_called_once()
    
    @patch('pck67_pkg.client.requests.request')
    def test_init_run(self, mock_request, client, mock_run_data):
        """Test initializing run"""
        mock_response = Mock()
        mock_response.json.return_value = mock_run_data
        mock_request.return_value = mock_response
        
        run = client.init_run(1, "test_run", {"lr": 0.001})
        
        assert isinstance(run, Run)
        assert run.name == "test_run"
        assert run.status == "running"
    
    @patch('pck67_pkg.client.requests.request')
    def test_log_metric(self, mock_request, client):
        """Test logging metric"""
        mock_response = Mock()
        mock_response.json.return_value = {"id": 1, "name": "loss", "value": 0.5, "step": 0}
        mock_request.return_value = mock_response
        
        result = client.log_metric(1, "loss", 0.5, 0)
        
        assert result["name"] == "loss"
        mock_request.assert_called_once()
    
    @patch('pck67_pkg.client.requests.request')
    def test_health_check(self, mock_request, client):
        """Test health check"""
        mock_response = Mock()
        mock_response.json.return_value = {"status": "healthy"}
        mock_request.return_value = mock_response
        
        result = client.health_check()
        
        assert result["status"] == "healthy"


class TestRun:
    
    def test_run_initialization(self, mock_run_data):
        """Test Run initialization"""
        mock_client = Mock()
        run = Run(mock_client, mock_run_data)
        
        assert run.id == 1
        assert run.name == "test_run"
        assert run.status == "running"
    
    def test_run_log_metric(self, mock_run_data):
        """Test Run.log_metric"""
        mock_client = Mock()
        mock_client.log_metric.return_value = {"id": 1, "name": "loss"}
        run = Run(mock_client, mock_run_data)
        
        result = run.log_metric("loss", 0.5, 1)
        
        mock_client.log_metric.assert_called_once_with(1, "loss", 0.5, 1)
    
    def test_run_finish(self, mock_run_data):
        """Test Run.finish"""
        mock_client = Mock()
        mock_client.finish_run.return_value = {"message": "Run finished"}
        run = Run(mock_client, mock_run_data)
        
        result = run.finish()
        
        assert run.status == "finished"
        mock_client.finish_run.assert_called_once_with(1)
    
    def test_run_str_repr(self, mock_run_data):
        """Test Run string representation"""
        mock_client = Mock()
        run = Run(mock_client, mock_run_data)
        
        assert "test_run" in str(run)
        assert "running" in repr(run)