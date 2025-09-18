import datetime
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class ReportingService:
    """Handles report generation operations."""

    @staticmethod
    def generate_report(data: List[Dict[str, Any]], errors: List[str]) -> Dict[str, Any]:
        """Generate processing report."""
        report = {
            'total_records': len(data),
            'valid_emails': sum(1 for r in data if r.get('email_valid', False)),
            'valid_phones': sum(1 for r in data if r.get('phone_valid', False)),
            'error_count': len(errors),
            'generated_at': datetime.datetime.now().isoformat(),
            'generated_by': 'system'
        }

        logger.info(f"Generated report: {report['total_records']} records processed")
        return report