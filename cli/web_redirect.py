"""
Web Redirect Module for CLI
Redirect users to web interface for features that can't be done in CLI
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
import webbrowser

console = Console()


def open_web_interface(feature: str = None):
    """
    Open web interface in browser
    
    Args:
        feature: Specific feature to navigate to (optional)
    """
    
    base_url = "http://localhost:5173"
    
    feature_urls = {
        'dashboard': f"{base_url}/dashboard",
        'attack': f"{base_url}/attack",
        'c2': f"{base_url}/c2",
        'targets': f"{base_url}/targets",
        'agents': f"{base_url}/agents",
        'logs': f"{base_url}/logs",
        'statistics': f"{base_url}/statistics",
        'knowledge': f"{base_url}/knowledge",
        'zeroday': f"{base_url}/zeroday",
        'settings': f"{base_url}/settings",
    }
    
    if feature and feature in feature_urls:
        url = feature_urls[feature]
        feature_name = feature.title()
    else:
        url = base_url
        feature_name = "Dashboard"
    
    # Display message
    message = Text()
    message.append("🌐 Opening Web Interface...\n\n", style="bold cyan")
    message.append(f"Feature: ", style="white")
    message.append(f"{feature_name}\n", style="bold green")
    message.append(f"URL: ", style="white")
    message.append(f"{url}\n\n", style="bold yellow")
    message.append("💡 Tip: ", style="bold blue")
    message.append("Some advanced features are better accessed through the web interface.\n", style="dim white")
    message.append("The web UI provides:\n", style="dim white")
    message.append("  • Real-time attack visualization\n", style="dim green")
    message.append("  • Interactive network maps\n", style="dim green")
    message.append("  • Drag-and-drop exploit builder\n", style="dim green")
    message.append("  • Live log streaming\n", style="dim green")
    message.append("  • Advanced statistics & charts\n", style="dim green")
    
    panel = Panel(
        message,
        title="[bold cyan]🚀 Web Interface[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    )
    
    console.print(panel)
    
    # Open browser
    try:
        webbrowser.open(url)
        console.print("✅ Browser opened successfully!", style="bold green")
    except Exception as e:
        console.print(f"❌ Failed to open browser: {e}", style="bold red")
        console.print(f"Please manually open: {url}", style="yellow")


def show_web_redirect_message(feature_name: str, reason: str = None):
    """
    Show message that feature requires web interface
    
    Args:
        feature_name: Name of the feature
        reason: Reason why CLI can't handle it (optional)
    """
    
    message = Text()
    message.append(f"⚠️  {feature_name}\n\n", style="bold yellow")
    
    if reason:
        message.append(f"Reason: {reason}\n\n", style="dim white")
    else:
        message.append("This feature requires the web interface for better user experience.\n\n", style="dim white")
    
    message.append("Would you like to open the web interface?\n", style="white")
    message.append("(Press Enter to continue, or Ctrl+C to cancel)", style="dim white")
    
    panel = Panel(
        message,
        title="[bold yellow]🌐 Web Interface Required[/bold yellow]",
        border_style="yellow",
        padding=(1, 2)
    )
    
    console.print(panel)
    
    try:
        input()
        return True
    except KeyboardInterrupt:
        console.print("\n❌ Cancelled", style="bold red")
        return False


def get_web_feature_url(feature: str) -> str:
    """
    Get URL for specific web feature
    
    Args:
        feature: Feature name
    
    Returns:
        Full URL to the feature
    """
    
    base_url = "http://localhost:5173"
    
    feature_urls = {
        'dashboard': f"{base_url}/dashboard",
        'attack': f"{base_url}/attack",
        'c2': f"{base_url}/c2",
        'targets': f"{base_url}/targets",
        'agents': f"{base_url}/agents",
        'logs': f"{base_url}/logs",
        'statistics': f"{base_url}/statistics",
        'knowledge': f"{base_url}/knowledge",
        'zeroday': f"{base_url}/zeroday",
        'settings': f"{base_url}/settings",
    }
    
    return feature_urls.get(feature, base_url)


# Features that require web interface
WEB_ONLY_FEATURES = {
    'network_map': {
        'name': 'Network Topology Map',
        'reason': 'Interactive network visualization requires graphical interface'
    },
    'attack_tree': {
        'name': 'Attack Tree Visualization',
        'reason': 'Complex tree structure is better viewed in graphical interface'
    },
    'exploit_builder': {
        'name': 'Interactive Exploit Builder',
        'reason': 'Drag-and-drop interface requires web UI'
    },
    'live_charts': {
        'name': 'Live Statistics Charts',
        'reason': 'Real-time charts require graphical interface'
    },
    'video_analysis': {
        'name': 'Video/Screenshot Analysis',
        'reason': 'Media playback requires web interface'
    },
}


def is_web_only_feature(feature: str) -> bool:
    """
    Check if feature requires web interface
    
    Args:
        feature: Feature name
    
    Returns:
        True if web-only, False otherwise
    """
    return feature in WEB_ONLY_FEATURES


def handle_web_only_feature(feature: str):
    """
    Handle request for web-only feature
    
    Args:
        feature: Feature name
    """
    
    if feature not in WEB_ONLY_FEATURES:
        console.print(f"❌ Unknown feature: {feature}", style="bold red")
        return
    
    feature_info = WEB_ONLY_FEATURES[feature]
    
    if show_web_redirect_message(feature_info['name'], feature_info['reason']):
        open_web_interface(feature)

