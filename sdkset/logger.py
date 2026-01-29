import os
import logging
from functools import wraps
from contextlib import contextmanager
from typing import Optional, Dict, Any
from pck67_pkg import TrackingClient

# Load environment variables from .env file if it exists
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                os.environ[key] = value


class TrackingHandler(logging.Handler):
    """Custom logging handler that logs to TrackingClient"""

    def __init__(self, client: TrackingClient, run_id: int):
        super().__init__()
        self.client = client
        self.run_id = run_id
        self.step_counter = 0

    def emit(self, record):
        """Send log record to tracking client"""
        try:
            log_entry = self.format(record)
            self.step_counter += 1
            self.client.log_message(self.run_id, log_entry, step=self.step_counter)
        except Exception:
            self.handleError(record)


def setup_tracking_logger(
    client: TrackingClient,
    run_id: int,
    name: str = "tracking",
    level: int = logging.INFO,
    console_output: bool = True
) -> logging.Logger:
    """
    Setup a logger that logs to both console and tracking client

    Args:
        client: TrackingClient instance
        run_id: Run ID to log to
        name: Logger name
        level: Logging level (default: INFO)
        console_output: Whether to also log to console (default: True)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()

    # Add tracking handler
    tracking_handler = TrackingHandler(client, run_id)
    tracking_formatter = logging.Formatter(
        '%(levelname)s: %(message)s'
    )
    tracking_handler.setFormatter(tracking_formatter)
    logger.addHandler(tracking_handler)

    # Optionally add console handler
    if console_output:
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    return logger


class TrackingManager:
    """
    A singleton class to manage tracking client connections and provide utilities
    for automatic logging setup in different modules.
    """

    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(TrackingManager, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self.client = None
            self.team_id = None
            self.project_id = None
            self.run = None
            self.logger = None
            self._initialized = True

    def initialize_client(
        self,
        api_key: Optional[str] = None,
        team_name: str = "Default Team",
        team_description: str = "Default team for experiments",
        project_name: str = "Default Project",
        project_description: str = "Default project for experiments",
        run_name: str = "Default Run",
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the tracking client with automatic team/project/run creation
        If team or project already exists, use the existing one instead of creating a new one
        """
        if config is None:
            config = {}

        # Get API key from parameter or environment variable
        if api_key is None:
            api_key = os.getenv("TRACKING_API_KEY")
            if not api_key:
                raise ValueError("API key must be provided or set in TRACKING_API_KEY environment variable")

        try:
            self.client = TrackingClient(api_key=api_key)

            # Get or create team - reuse existing if it exists
            teams = self.client.list_teams()
            team_found = False
            for team in teams:
                if team['name'] == team_name:
                    self.team_id = team['id']
                    team_found = True
                    break

            if not team_found:
                team = self.client.create_team(team_name, team_description)
                self.team_id = team['id']

            # Get or create project - reuse existing if it exists
            projects = self.client.list_projects(self.team_id)
            project_found = False
            for project in projects:
                if project['name'] == project_name:
                    self.project_id = project['id']
                    project_found = True
                    break

            if not project_found:
                project = self.client.create_project(self.team_id, project_name, project_description)
                self.project_id = project['id']

            # Start a run
            self.run = self.client.init_run(
                project_id=self.project_id,
                name=run_name,
                config=config
            )

            # Setup logger
            self.logger = setup_tracking_logger(
                self.client,
                self.run.id,
                name=f"{project_name.lower().replace(' ', '_')}_logger",
                level=logging.DEBUG
            )

            return self.logger

        except Exception as e:
            print(f"Error initializing tracking client: {e}")
            print("The tracking server might be temporarily unavailable. Please try again later.")
            return None

    def get_logger(self):
        """Get the initialized logger"""
        return self.logger

    def get_client(self):
        """Get the tracking client"""
        return self.client

    def get_run(self):
        """Get the current run"""
        return self.run


def with_tracking(
    team_name: str = "Default Team",
    team_description: str = "Default team for experiments",
    project_name: str = "Default Project",
    project_description: str = "Default project for experiments",
    run_name: str = "Default Run",
    config: Optional[Dict[str, Any]] = None,
    api_key: Optional[str] = None
):
    """
    Decorator to automatically set up tracking for any function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Initialize tracking manager
            tracker = TrackingManager()
            logger = tracker.initialize_client(
                api_key=api_key,
                team_name=team_name,
                team_description=team_description,
                project_name=project_name,
                project_description=project_description,
                run_name=run_name,
                config=config
            )

            if logger:
                # Add logger to kwargs so the function can use it
                kwargs['logger'] = logger

            # Execute the original function
            result = func(*args, **kwargs)
            return result
        return wrapper
    return decorator


@contextmanager
def tracking_context(
    team_name: str = "Default Team",
    team_description: str = "Default team for experiments",
    project_name: str = "Default Project",
    project_description: str = "Default project for experiments",
    run_name: str = "Default Run",
    config: Optional[Dict[str, Any]] = None,
    api_key: Optional[str] = None
):
    """
    Context manager to automatically set up tracking for a block of code
    """
    tracker = TrackingManager()
    logger = tracker.initialize_client(
        api_key=api_key,
        team_name=team_name,
        team_description=team_description,
        project_name=project_name,
        project_description=project_description,
        run_name=run_name,
        config=config
    )

    try:
        yield logger
    except Exception as e:
        if logger:
            logger.error(f"Error in tracking context: {e}")
        raise
    finally:
        # Cleanup if needed
        pass


def auto_track_module(
    module_name: str,
    team_name: str = "Unilogger Team",
    team_description: str = "Shared team for unilogger project",
    project_name: str = "Unilogger Project",
    project_description: str = "Main project for unilogger experiments",
    run_name: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None
):
    """
    Function to automatically set up tracking for an entire module
    Uses shared team and project across modules, with unique runs
    Call this at the beginning of any module that needs tracking
    """
    tracker = TrackingManager()

    # Use module name as run name if not specified
    if run_name is None:
        run_name = f"{module_name.title()} Run - {os.getpid()}"  # Include PID to make unique

    logger = tracker.initialize_client(
        team_name=team_name,
        team_description=team_description,
        project_name=project_name,
        project_description=project_description,
        run_name=run_name,
        config=config or {"module": module_name}
    )

    return logger