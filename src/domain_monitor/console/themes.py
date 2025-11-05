"""Theme configuration for Rich console output.

This module defines color schemes, icons, and Rich themes for consistent
visual presentation throughout the application.
"""

from rich.theme import Theme

# Status color mappings
STATUS_COLORS = {
    'OK': 'green',
    'WARNING': 'yellow',
    'ERROR': 'red',
    'CRITICAL': 'bold red'
}

# Unicode icons for various status indicators
ICONS = {
    'success': '✓',
    'error': '✗',
    'warning': '⚠',
    'info': 'ℹ',
    'time': '⏱',
    'domain': '🌐',
    'check': '🔍'
}


def get_theme() -> Theme:
    """Get the Rich theme with custom styles.
    
    Returns:
        Theme: Rich Theme object with custom style definitions
    """
    return Theme({
        "info": "cyan",
        "warning": "yellow",
        "error": "bold red",
        "success": "bold green",
        "domain": "bold cyan",
        "check_type": "magenta",
        "timestamp": "dim",
        "metric": "blue"
    })
