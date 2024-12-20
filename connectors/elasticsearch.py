from elasticsearch import Elasticsearch
from typing import Dict, List, Optional
from datetime import datetime, timedelta

class ElasticsearchConnector:
    def __init__(
        self,
        host: str,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = True
    ):
        """
        Initialize Elasticsearch connector with either API key or username/password authentication.
        
        Args:
            host: Elasticsearch host URL (e.g., 'https://elasticsearch.example.com')
            api_key: API key for authentication
            username: Username for basic authentication
            password: Password for basic authentication
            verify_ssl: Whether to verify SSL certificates
        """
        # Configure authentication
        if api_key:
            auth = {'api_key': api_key}
        elif username and password:
            auth = {'basic_auth': (username, password)}
        else:
            raise ValueError("Either API key or username/password must be provided")

        # Initialize Elasticsearch client
        self.client = Elasticsearch(
            hosts=[host],
            verify_certs=verify_ssl,
            **auth
        )

    def get_signals(self, space: str = "default", days: int = 30) -> List[Dict]:
        """
        Retrieve security signals/alerts for the last X days using scroll API.
        
        Args:
            space: Kibana space name (default: 'default')
            days: Number of days to look back (default: 30)
        """
        index_pattern = f".internal.alerts-security.alerts-{space}-*"
        
        # Calculate the date range
        now = datetime.utcnow()
        date_from = (now - timedelta(days=days)).isoformat()

        # Build the query
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": date_from}}}
                ]
            }
        }

        # Initialize scroll
        results = []
        resp = self.client.search(
            index=index_pattern,
            query=query,
            scroll='5m',  # Keep the search context alive for 5 minutes
            size=1000,    # Number of documents per batch
            sort=[{"@timestamp": {"order": "desc"}}]
        )
        
        # Get the scroll ID
        scroll_id = resp['_scroll_id']
        
        # Get the first batch of results
        results.extend([{
            'id': hit['_id'],
            'source': hit['_source']
        } for hit in resp['hits']['hits']])
        
        # Continue scrolling until no more hits are returned
        while len(resp['hits']['hits']):
            resp = self.client.scroll(
                scroll_id=scroll_id,
                scroll='5m'
            )
            results.extend([{
                'id': hit['_id'],
                'source': hit['_source']
            } for hit in resp['hits']['hits']])
        
        # Clear the scroll context to free up resources
        self.client.clear_scroll(scroll_id=scroll_id)
        
        return results

    def get_signal_by_id(self, signal_id: str, space: str = "default") -> Dict:
        """
        Retrieve a specific security signal/alert by ID.
        
        Args:
            signal_id: The ID of the signal to retrieve
            space: Kibana space name (default: 'default')
        """
        index_pattern = f".internal.alerts-security.alerts-{space}-*"
        
        # Build the query
        query = {
            "bool": {
                "must": [
                    {"term": {"_id": signal_id}}
                ]
            }
        }

        # Execute the search
        response = self.client.search(
            index=index_pattern,
            query=query
        )

        if response['hits']['total']['value'] == 0:
            raise ValueError(f"Signal with ID {signal_id} not found")

        return {
            'id': response['hits']['hits'][0]['_id'],
            'source': response['hits']['hits'][0]['_source']
        }
