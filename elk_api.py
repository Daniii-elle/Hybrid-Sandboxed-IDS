"""
ELK API Client for IDS System
Provides structured API interface for Elasticsearch operations
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ELKClient:
    """Enhanced ELK API client for IDS operations"""

    def __init__(self, base_url: str = "http://localhost:9201", timeout: int = 20):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict]:
        """Make HTTP request with error handling"""
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.request(method, url, timeout=self.timeout, **kwargs)
            response.raise_for_status()
            return response.json() if response.content else {}
        except requests.exceptions.RequestException as e:
            logger.error(f"ELK API request failed: {method} {url} - {e}")
            return None

    def health_check(self) -> bool:
        """Check if Elasticsearch is healthy"""
        result = self._make_request('GET', '/_cluster/health')
        if result:
            status = result.get('status', 'red')
            logger.info(f"Elasticsearch health: {status}")
            return status in ['yellow', 'green']
        return False

    def create_index(self, index_name: str, mapping: Optional[Dict] = None) -> bool:
        """Create an index with optional mapping"""
        if mapping is None:
            mapping = {
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "event_type": {"type": "keyword"},
                        "data": {"type": "object"},
                        "severity": {"type": "keyword"},
                        "source_ip": {"type": "ip"},
                        "destination_ip": {"type": "ip"},
                        "anomaly_score": {"type": "float"}
                    }
                }
            }

        result = self._make_request('PUT', f'/{index_name}', json=mapping)
        if result and result.get('acknowledged'):
            logger.info(f"Created index: {index_name}")
            return True
        return False

    def index_exists(self, index_name: str) -> bool:
        """Check if index exists"""
        response = self.session.head(f"{self.base_url}/{index_name}", timeout=self.timeout)
        return response.status_code == 200

    def delete_index(self, index_name: str) -> bool:
        """Delete an index"""
        result = self._make_request('DELETE', f'/{index_name}')
        if result and result.get('acknowledged'):
            logger.info(f"Deleted index: {index_name}")
            return True
        return False

    def index_document(self, index_name: str, document: Dict, doc_id: Optional[str] = None) -> bool:
        """Index a single document"""
        endpoint = f'/{index_name}/_doc'
        if doc_id:
            endpoint = f'/{index_name}/_doc/{doc_id}'

        payload = {
            "@timestamp": datetime.now().isoformat(),
            **document
        }

        result = self._make_request('POST', endpoint, json=payload)
        if result and result.get('_id'):
            logger.debug(f"Indexed document in {index_name}: {result['_id']}")
            return True
        return False

    def bulk_index(self, index_name: str, documents: List[Dict]) -> bool:
        """Bulk index multiple documents"""
        bulk_data = []
        for doc in documents:
            # Add index metadata
            bulk_data.append({"index": {"_index": index_name}})
            # Add document with timestamp
            bulk_data.append({
                "@timestamp": datetime.now().isoformat(),
                **doc
            })

        # Convert to NDJSON format
        ndjson_data = '\n'.join(json.dumps(item) for item in bulk_data) + '\n'

        try:
            response = self.session.post(
                f"{self.base_url}/_bulk",
                data=ndjson_data,
                headers={'Content-Type': 'application/x-ndjson'},
                timeout=self.timeout
            )
            response.raise_for_status()
            result = response.json()

            if not result.get('errors', True):
                logger.info(f"Bulk indexed {len(documents)} documents to {index_name}")
                return True
            else:
                logger.error(f"Bulk indexing errors: {result}")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Bulk indexing failed: {e}")
            return False

    def search(self, index_name: str, query: Optional[Dict] = None, size: int = 10) -> Optional[List[Dict]]:
        """Search documents in an index"""
        if query is None:
            query = {"match_all": {}}

        payload = {
            "query": query,
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}]
        }

        result = self._make_request('POST', f'/{index_name}/_search', json=payload)
        if result and 'hits' in result:
            return result['hits']['hits']
        return None

    def search_anomalies(self, index_name: str, hours: int = 24, size: int = 100) -> Optional[List[Dict]]:
        """Search for anomalies in the last N hours"""
        query = {
            "bool": {
                "must": [
                    {"term": {"event_type": "anomaly"}}
                ],
                "filter": {
                    "range": {
                        "@timestamp": {
                            "gte": f"now-{hours}h",
                            "lte": "now"
                        }
                    }
                }
            }
        }
        return self.search(index_name, query, size)

    def search_alerts(self, index_name: str, severity: Optional[str] = None, hours: int = 24) -> Optional[List[Dict]]:
        """Search for alerts with optional severity filter"""
        must_conditions = [{"term": {"event_type": "suricata_alert"}}]

        if severity:
            must_conditions.append({"term": {"severity": severity}})

        query = {
            "bool": {
                "must": must_conditions,
                "filter": {
                    "range": {
                        "@timestamp": {
                            "gte": f"now-{hours}h",
                            "lte": "now"
                        }
                    }
                }
            }
        }
        return self.search(index_name, query)

    def get_stats(self, index_name: str) -> Optional[Dict]:
        """Get index statistics"""
        return self._make_request('GET', f'/{index_name}/_stats')

    def create_dashboard_template(self, index_name: str) -> Dict:
        """Generate Kibana dashboard configuration"""
        return {
            "index_pattern": {
                "title": f"{index_name}-*",
                "timeFieldName": "@timestamp"
            },
            "visualizations": [
                {
                    "title": "Anomaly Timeline",
                    "type": "line",
                    "query": {"term": {"event_type": "anomaly"}}
                },
                {
                    "title": "Alert Severity Distribution",
                    "type": "pie",
                    "query": {"term": {"event_type": "suricata_alert"}}
                }
            ]
        }


# Global ELK client instance
elk_client = ELKClient()


def initialize_elk_indices():
    """Initialize required indices for IDS system"""
    indices = {
        "ids-anomalies": "Anomaly detection results",
        "ids-alerts": "Suricata alerts",
        "ids-events": "General security events"
    }

    for index_name, description in indices.items():
        if not elk_client.index_exists(index_name):
            if elk_client.create_index(index_name):
                logger.info(f"Created {description} index: {index_name}")
            else:
                logger.error(f"Failed to create {description} index: {index_name}")


def send_anomaly_to_elk(anomaly_data: Dict) -> bool:
    """Send anomaly data to ELK"""
    return elk_client.index_document("ids-anomalies", {
        "event_type": "anomaly",
        **anomaly_data
    })


def send_alert_to_elk(alert_data: Dict) -> bool:
    """Send alert data to ELK"""
    return elk_client.index_document("ids-alerts", {
        "event_type": "suricata_alert",
        **alert_data
    })


def send_event_to_elk(event_data: Dict, event_type: str = "general") -> bool:
    """Send general event data to ELK"""
    return elk_client.index_document("ids-events", {
        "event_type": event_type,
        **event_data
    })


def get_recent_anomalies(hours: int = 24, limit: int = 50) -> Optional[List[Dict]]:
    """Get recent anomalies from ELK"""
    return elk_client.search_anomalies("ids-anomalies", hours, limit)


def get_recent_alerts(severity: Optional[str] = None, hours: int = 24) -> Optional[List[Dict]]:
    """Get recent alerts from ELK"""
    return elk_client.search_alerts("ids-alerts", severity, hours)


def get_elk_health() -> Dict:
    """Get ELK system health status"""
    return {
        "elasticsearch_healthy": elk_client.health_check(),
        "indices": {
            "anomalies": elk_client.index_exists("ids-anomalies"),
            "alerts": elk_client.index_exists("ids-alerts"),
            "events": elk_client.index_exists("ids-events")
        }
    }


if __name__ == "__main__":
    # Test ELK connection
    if elk_client.health_check():
        print("ELK connection successful")
        initialize_elk_indices()
    else:
        print("ELK connection failed")