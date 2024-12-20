import requests
from typing import Dict, List, Optional, Union
from urllib3.exceptions import InsecureRequestWarning

# Suppress insecure HTTPS warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class KibanaConnector:
    def __init__(
        self,
        host: str,
        space: str = "default",
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = True
    ):
        """
        Initialize Kibana connector with either API key or username/password authentication.
        
        Args:
            host: Kibana host URL (e.g., 'https://kibana.example.com')
            space: Kibana space name (default: 'default')
            api_key: API key for authentication
            username: Username for basic authentication
            password: Password for basic authentication
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = host.rstrip('/')
        self.space = space
        self.verify_ssl = verify_ssl
        
        # Set up authentication headers
        self.headers = {'kbn-xsrf': 'true'}
        if api_key:
            self.headers['Authorization'] = f'ApiKey {api_key}'
        elif username and password:
            self.auth = (username, password)
        else:
            raise ValueError("Either API key or username/password must be provided")
            
        # Set space-aware API endpoint
        self.api_endpoint = (
            f"{self.base_url}/s/{space}/api"
            if space != "default"
            else f"{self.base_url}/api"
        )

    def get_all_detection_rules(self) -> List[Dict]:
        """Retrieve all detection rules from Kibana."""
        url = f"{self.api_endpoint}/detection_engine/rules/_find"
        
        all_rules = []
        page = 1
        per_page = 100  # Increase page size to reduce number of requests
        
        while True:
            params = {
                'page': page,
                'per_page': per_page
            }
            
            response = requests.get(
                url,
                headers=self.headers,
                params=params,
                verify=self.verify_ssl,
                auth=getattr(self, 'auth', None)
            )
            response.raise_for_status()
            
            data = response.json()
            rules = data['data']
            all_rules.extend(rules)
            
            # Break if we've received fewer rules than the page size
            # (indicating we've reached the end)
            if len(rules) < per_page:
                break
                
            page += 1
            
        return all_rules

    def get_rule(self, rule_id: str) -> Dict:
        """
        Retrieve a specific detection rule by rule_id.
        
        Args:
            rule_id: The ID of the rule to retrieve
        """
        url = f"{self.api_endpoint}/detection_engine/rules"
        params = {'rule_id': rule_id}
        
        response = requests.get(
            url,
            headers=self.headers,
            params=params,
            verify=self.verify_ssl,
            auth=getattr(self, 'auth', None)
        )
        response.raise_for_status()
        return response.json()

    def patch_rule(self, rule_id: str, updates: Dict) -> Dict:
        """
        Update a detection rule using PATCH method.
        
        Args:
            rule_id: The ID of the rule to update
            updates: Dictionary containing the fields to update
        """
        url = f"{self.api_endpoint}/detection_engine/rules"
        payload = {
            "rule_id": rule_id,
            **updates
        }

        response = requests.patch(
            url,
            headers=self.headers,
            json=payload,
            verify=self.verify_ssl,
            auth=getattr(self, 'auth', None)
        )
        response.raise_for_status()
        return response.json()

    def add_note(self, event_id: str, note_text: str, timeline_id: str = "") -> Dict:
        """
        Add a note to a specific alert/event in Kibana.
        
        Args:
            event_id: The ID of the alert/event
            note_text: The content of the note to add
            timeline_id: Optional timeline ID (default: empty string)
        """
        url = f"{self.api_endpoint}/note"
        payload = {
            "note": {
                "timelineId": timeline_id,
                "eventId": event_id,
                "note": note_text
            }
        }

        response = requests.patch(
            url,
            headers=self.headers,
            json=payload,
            verify=self.verify_ssl,
            auth=getattr(self, 'auth', None)
        )
        response.raise_for_status()
        return response.json()
