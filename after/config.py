import os
from dataclasses import dataclass
from typing import List

@dataclass
class DatabaseConfig:
    driver: str
    server: str
    database: str
    username: str
    password: str

    @property
    def connection_string(self) -> str:
        return f"DRIVER={{{self.driver}}};SERVER={self.server};DATABASE={self.database};UID={self.username};PWD={self.password}"

@dataclass
class LDAPConfig:
    server: str
    username: str
    password: str
    base_dn: str = "dc=company,dc=com"

@dataclass
class APIConfig:
    api_key: str
    secret_key: str
    encryption_key: str

@dataclass
class BackupConfig:
    urls: List[str]

@dataclass
class AppConfig:
    database: DatabaseConfig
    ldap: LDAPConfig
    api: APIConfig
    backup: BackupConfig
    admin_password: str

def load_config() -> AppConfig:
    """Load configuration from environment variables with fallback defaults for demo purposes."""

    database_config = DatabaseConfig(
        driver=os.getenv("DB_DRIVER", "ODBC Driver 17 for SQL Server"),
        server=os.getenv("DB_SERVER", "localhost"),
        database=os.getenv("DB_DATABASE", "TestDB"),
        username=os.getenv("DB_USERNAME", "testuser"),
        password=os.getenv("DB_PASSWORD", "testpass")
    )

    ldap_config = LDAPConfig(
        server=os.getenv("LDAP_SERVER", "ldap://localhost:389"),
        username=os.getenv("LDAP_USERNAME", "testadmin"),
        password=os.getenv("LDAP_PASSWORD", "testpass"),
        base_dn=os.getenv("LDAP_BASE_DN", "dc=company,dc=com")
    )

    api_config = APIConfig(
        api_key=os.getenv("API_KEY", "test-api-key"),
        secret_key=os.getenv("SECRET_KEY", "test-secret-key"),
        encryption_key=os.getenv("ENCRYPTION_KEY", "test-encryption-key")
    )

    backup_config = BackupConfig(
        urls=os.getenv("BACKUP_URLS", "http://localhost:8080,http://localhost:8081").split(",")
    )

    return AppConfig(
        database=database_config,
        ldap=ldap_config,
        api=api_config,
        backup=backup_config,
        admin_password=os.getenv("ADMIN_PASSWORD", "testadmin")
    )