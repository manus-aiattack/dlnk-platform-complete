#!/usr/bin/env python3.11
"""
dLNk Attack Platform - CLI Client
Command-line interface for controlling the attack platform
"""

import requests
import json
import sys
import argparse
from typing import Optional, Dict, Any
from datetime import datetime
import time


class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class DLNkCLI:
    """CLI Client for dLNk Attack Platform"""
    
    def __init__(self, base_url: str = "https://8000-i3ahfavoia7c7k1dxwwpn-567d442b.manus-asia.computer", api_key: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.headers = {}
        if api_key:
            self.headers['X-API-Key'] = api_key
    
    def _print_success(self, message: str):
        print(f"{Colors.OKGREEN}✓ {message}{Colors.ENDC}")
    
    def _print_error(self, message: str):
        print(f"{Colors.FAIL}✗ {message}{Colors.ENDC}")
    
    def _print_info(self, message: str):
        print(f"{Colors.OKCYAN}ℹ {message}{Colors.ENDC}")
    
    def _print_warning(self, message: str):
        print(f"{Colors.WARNING}⚠ {message}{Colors.ENDC}")
    
    def _print_header(self, message: str):
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}{message}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}\n")
    
    def _request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Make HTTP request to API"""
        url = f"{self.base_url}{endpoint}"
        try:
            response = requests.request(method, url, headers=self.headers, **kwargs)
            response.raise_for_status()
            return response.json() if response.content else {}
        except requests.exceptions.HTTPError as e:
            self._print_error(f"HTTP Error: {e}")
            if e.response.content:
                try:
                    error_data = e.response.json()
                    self._print_error(f"Details: {error_data.get('detail', 'Unknown error')}")
                except:
                    pass
            return None
        except requests.exceptions.ConnectionError:
            self._print_error("Connection error. Is the server running?")
            return None
        except Exception as e:
            self._print_error(f"Error: {e}")
            return None
    
    def health_check(self):
        """Check server health"""
        self._print_header("🏥 Health Check")
        data = self._request('GET', '/health')
        if data:
            self._print_success("Server is healthy")
            print(f"  Version: {data.get('version', 'unknown')}")
            print(f"  Timestamp: {data.get('timestamp', 'unknown')}")
            print(f"  Targets: {data.get('targets_count', 0)}")
            print(f"  Campaigns: {data.get('campaigns_count', 0)}")
            return True
        return False
    
    def list_targets(self):
        """List all targets"""
        self._print_header("🎯 Targets")
        data = self._request('GET', '/api/targets')
        if data:
            targets = data.get('targets', [])
            if not targets:
                self._print_info("No targets found")
            else:
                for target in targets:
                    print(f"\n{Colors.BOLD}ID:{Colors.ENDC} {target['target_id']}")
                    print(f"{Colors.BOLD}Name:{Colors.ENDC} {target['name']}")
                    print(f"{Colors.BOLD}URL:{Colors.ENDC} {target['url']}")
                    if target.get('description'):
                        print(f"{Colors.BOLD}Description:{Colors.ENDC} {target['description']}")
                    print(f"{Colors.BOLD}Created:{Colors.ENDC} {target['created_at']}")
                    print("-" * 60)
            return True
        return False
    
    def create_target(self, name: str, url: str, description: Optional[str] = None):
        """Create a new target"""
        self._print_header("➕ Create Target")
        params = {
            'name': name,
            'url': url
        }
        if description:
            params['description'] = description
        
        data = self._request('POST', '/api/targets', params=params)
        if data:
            self._print_success(f"Target created: {data['target_id']}")
            print(f"  Name: {data['name']}")
            print(f"  URL: {data['url']}")
            return True
        return False
    
    def delete_target(self, target_id: str):
        """Delete a target"""
        self._print_header("🗑️  Delete Target")
        data = self._request('DELETE', f'/api/targets/{target_id}')
        if data is not None:
            self._print_success(f"Target deleted: {target_id}")
            return True
        return False
    
    def list_campaigns(self):
        """List all campaigns"""
        self._print_header("⚔️  Campaigns")
        data = self._request('GET', '/api/campaigns')
        if data:
            campaigns = data.get('campaigns', [])
            if not campaigns:
                self._print_info("No campaigns found")
            else:
                for campaign in campaigns:
                    status_color = {
                        'pending': Colors.WARNING,
                        'running': Colors.OKCYAN,
                        'completed': Colors.OKGREEN,
                        'failed': Colors.FAIL
                    }.get(campaign['status'], Colors.ENDC)
                    
                    print(f"\n{Colors.BOLD}ID:{Colors.ENDC} {campaign['campaign_id']}")
                    print(f"{Colors.BOLD}Name:{Colors.ENDC} {campaign['name']}")
                    print(f"{Colors.BOLD}Status:{Colors.ENDC} {status_color}{campaign['status'].upper()}{Colors.ENDC}")
                    print(f"{Colors.BOLD}Phase:{Colors.ENDC} {campaign['current_phase']}")
                    print(f"{Colors.BOLD}Progress:{Colors.ENDC} {campaign['progress']:.1f}%")
                    
                    if campaign.get('started_at'):
                        print(f"{Colors.BOLD}Started:{Colors.ENDC} {campaign['started_at']}")
                    if campaign.get('completed_at'):
                        print(f"{Colors.BOLD}Completed:{Colors.ENDC} {campaign['completed_at']}")
                    if campaign.get('results'):
                        print(f"{Colors.BOLD}Results:{Colors.ENDC}")
                        for key, value in campaign['results'].items():
                            print(f"  - {key}: {value}")
                    print("-" * 60)
            return True
        return False
    
    def start_campaign(self, target_id: str, name: str = "CLI Campaign"):
        """Start a new campaign"""
        self._print_header("🚀 Start Campaign")
        params = {
            'target_id': target_id,
            'campaign_name': name
        }
        data = self._request('POST', '/api/campaigns/start', params=params)
        if data:
            self._print_success(f"Campaign started: {data['campaign_id']}")
            print(f"  Name: {data['name']}")
            print(f"  Target: {data['target']['name']}")
            print(f"  Status: {data['status']}")
            return data['campaign_id']
        return None
    
    def get_campaign_status(self, campaign_id: str):
        """Get campaign status"""
        data = self._request('GET', f'/api/campaigns/{campaign_id}/status')
        if data:
            return data
        return None
    
    def monitor_campaign(self, campaign_id: str, interval: int = 2):
        """Monitor campaign progress in real-time"""
        self._print_header(f"📊 Monitoring Campaign: {campaign_id}")
        self._print_info("Press Ctrl+C to stop monitoring\n")
        
        try:
            while True:
                status = self.get_campaign_status(campaign_id)
                if not status:
                    break
                
                # Clear previous line
                print("\033[F\033[K" * 4, end='')
                
                status_color = {
                    'pending': Colors.WARNING,
                    'running': Colors.OKCYAN,
                    'completed': Colors.OKGREEN,
                    'failed': Colors.FAIL
                }.get(status['status'], Colors.ENDC)
                
                print(f"{Colors.BOLD}Status:{Colors.ENDC} {status_color}{status['status'].upper()}{Colors.ENDC}")
                print(f"{Colors.BOLD}Phase:{Colors.ENDC} {status['current_phase']}")
                print(f"{Colors.BOLD}Progress:{Colors.ENDC} {status['progress']:.1f}%")
                
                # Progress bar
                bar_length = 40
                filled = int(bar_length * status['progress'] / 100)
                bar = '█' * filled + '░' * (bar_length - filled)
                print(f"[{bar}]")
                
                if status['status'] in ['completed', 'failed', 'cancelled']:
                    print()
                    if status['status'] == 'completed':
                        self._print_success("Campaign completed!")
                    else:
                        self._print_warning(f"Campaign {status['status']}")
                    break
                
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n")
            self._print_info("Monitoring stopped")
    
    def stop_campaign(self, campaign_id: str):
        """Stop a running campaign"""
        self._print_header("🛑 Stop Campaign")
        data = self._request('POST', f'/api/campaigns/{campaign_id}/stop')
        if data and data.get('success'):
            self._print_success(f"Campaign stopped: {campaign_id}")
            return True
        return False


def main():
    parser = argparse.ArgumentParser(
        description='dLNk Attack Platform - CLI Client',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --health
  %(prog)s --list-targets
  %(prog)s --create-target "Test Server" "https://example.com"
  %(prog)s --start-campaign <target_id>
  %(prog)s --monitor <campaign_id>
        """
    )
    
    parser.add_argument('--url', default='https://8000-i3ahfavoia7c7k1dxwwpn-567d442b.manus-asia.computer', help='API base URL')
    parser.add_argument('--api-key', help='API key for authentication')
    
    # Commands
    parser.add_argument('--health', action='store_true', help='Check server health')
    parser.add_argument('--list-targets', action='store_true', help='List all targets')
    parser.add_argument('--create-target', nargs='+', metavar=('NAME', 'URL'), help='Create a new target')
    parser.add_argument('--delete-target', metavar='ID', help='Delete a target')
    parser.add_argument('--list-campaigns', action='store_true', help='List all campaigns')
    parser.add_argument('--start-campaign', metavar='TARGET_ID', help='Start a new campaign')
    parser.add_argument('--campaign-name', default='CLI Campaign', help='Campaign name')
    parser.add_argument('--monitor', metavar='CAMPAIGN_ID', help='Monitor campaign progress')
    parser.add_argument('--stop-campaign', metavar='CAMPAIGN_ID', help='Stop a campaign')
    
    args = parser.parse_args()
    
    # Create CLI client
    cli = DLNkCLI(base_url=args.url, api_key=args.api_key)
    
    # Execute commands
    if args.health:
        cli.health_check()
    elif args.list_targets:
        cli.list_targets()
    elif args.create_target:
        if len(args.create_target) < 2:
            print("Error: --create-target requires NAME and URL")
            sys.exit(1)
        name = args.create_target[0]
        url = args.create_target[1]
        description = ' '.join(args.create_target[2:]) if len(args.create_target) > 2 else None
        cli.create_target(name, url, description)
    elif args.delete_target:
        cli.delete_target(args.delete_target)
    elif args.list_campaigns:
        cli.list_campaigns()
    elif args.start_campaign:
        campaign_id = cli.start_campaign(args.start_campaign, args.campaign_name)
        if campaign_id:
            print()
            response = input("Monitor this campaign? [y/N]: ")
            if response.lower() == 'y':
                cli.monitor_campaign(campaign_id)
    elif args.monitor:
        cli.monitor_campaign(args.monitor)
    elif args.stop_campaign:
        cli.stop_campaign(args.stop_campaign)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()

