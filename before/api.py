import ldap
import pyodbc
import json
import xml.etree.ElementTree as ET
import re
import hashlib
import base64
import datetime
import os
import logging

class API:
    def __init__(self):
        # Load sensitive information from environment variables
        self.ldap_server = os.getenv('LDAP_SERVER', 'ldap://localhost:389')
        self.ldap_user = os.getenv('LDAP_USER')
        self.ldap_password = os.getenv('LDAP_PASSWORD')
        
        # Build SQL connection string from environment variables
        self.sql_server = self._build_sql_connection_string()
        
        # Load API-related keys from environment variables
        self.api_key = os.getenv('API_KEY')
        self.secret_key = os.getenv('SECRET_KEY')
        self.encryption_key = os.getenv('ENCRYPTION_KEY')
        self.admin_password = os.getenv('ADMIN_PASSWORD')
        
        # Load backup URLs from environment variables
        backup_urls = os.getenv('BACKUP_URLS')
        self.backup_urls = backup_urls.split(',') if backup_urls else []
        
        # Validate required environment variables
        self._validate_environment()

    def _build_sql_connection_string(self):
        """Build SQL Server connection string"""
        return (
            f"DRIVER={{ODBC Driver 17 for SQL Server}};"
            f"SERVER={os.getenv('DB_SERVER', 'localhost')};"
            f"DATABASE={os.getenv('DB_NAME', 'master')};"
            f"UID={os.getenv('DB_USER')};"
            f"PWD={os.getenv('DB_PASSWORD')}"
        )

    def _validate_environment(self):
        """Validate that required environment variables are present"""
        required_vars = [
            ('LDAP_USER', 'LDAP username'),
            ('LDAP_PASSWORD', 'LDAP password'),
            ('DB_USER', 'Database username'),
            ('DB_PASSWORD', 'Database password'),
            ('API_KEY', 'API key'),
            ('SECRET_KEY', 'Secret key'),
            ('ENCRYPTION_KEY', 'Encryption key'),
            ('ADMIN_PASSWORD', 'Admin password')
        ]
        
        missing_vars = [
            desc for var, desc in required_vars
            if not os.getenv(var)
        ]
        
        if missing_vars:
            raise EnvironmentError(
                "Missing required environment variables:\n" +
                "\n".join(f"- {desc}" for desc in missing_vars)
            )
        self.connection = None
        self.ldap_conn = None
        self.data = []
        self.processed_data = []
        self.errors = []
        self.logs = []
        self.user_sessions = {}
        self.cached_results = {}
        self.config = {}
        self.temp_files = []

    def connect_ldap(self):
        try:
            self.ldap_conn = ldap.initialize(self.ldap_server)
            self.ldap_conn.simple_bind_s(self.ldap_user, self.ldap_password)
            return True
        except Exception as e:
            self.errors.append(f"LDAP Error: {str(e)}")
            return False

    def connect_sql(self):
        try:
            self.connection = pyodbc.connect(self.sql_server)
            return True
        except Exception as e:
            self.errors.append(f"SQL Error: {str(e)}")
            return False

    def authenticate_user(self, username, password):
        if username == "admin" and password == self.admin_password:
            return True
        if not self.connect_ldap():
            return False
        try:
            search_filter = f"(uid={username})"
            results = self.ldap_conn.search_s("dc=company,dc=com", ldap.SCOPE_SUBTREE, search_filter)
            if results:
                user_dn = results[0][0]
                self.ldap_conn.simple_bind_s(user_dn, password)
                return True
        except:
            pass
        return False

    def validate_email(self, email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def validate_phone(self, phone):
        cleaned = re.sub(r'[^\d]', '', phone)
        return len(cleaned) >= 10

    def validate_ssn(self, ssn):
        pattern = r'^\d{3}-\d{2}-\d{4}$'
        return re.match(pattern, ssn) is not None

    def validate_credit_card(self, cc):
        cleaned = re.sub(r'[^\d]', '', cc)
        return len(cleaned) == 16

    def parse_json_data(self, json_string):
        try:
            data = json.loads(json_string)
            self.data.append(data)
            return data
        except Exception as e:
            self.errors.append(f"JSON Parse Error: {str(e)}")
            return None

    def parse_xml_data(self, xml_string):
        try:
            root = ET.fromstring(xml_string)
            data = {}
            for child in root:
                data[child.tag] = child.text
            self.data.append(data)
            return data
        except Exception as e:
            self.errors.append(f"XML Parse Error: {str(e)}")
            return None

    def process_user_data(self, user_data):
        processed = {}
        processed['id'] = user_data.get('id', '')
        processed['name'] = user_data.get('name', '').upper()
        processed['email'] = user_data.get('email', '').lower()
        processed['phone'] = re.sub(r'[^\d]', '', user_data.get('phone', ''))
        processed['created_date'] = datetime.datetime.now().isoformat()

        if self.validate_email(processed['email']):
            processed['email_valid'] = True
        else:
            processed['email_valid'] = False
            self.errors.append(f"Invalid email: {processed['email']}")

        if self.validate_phone(processed['phone']):
            processed['phone_valid'] = True
        else:
            processed['phone_valid'] = False
            self.errors.append(f"Invalid phone: {processed['phone']}")

        self.processed_data.append(processed)
        return processed

    def encrypt_data(self, data):
        key = self.encryption_key.encode()
        data_bytes = str(data).encode()
        encrypted = base64.b64encode(data_bytes).decode()
        return encrypted

    def decrypt_data(self, encrypted_data):
        try:
            decrypted_bytes = base64.b64decode(encrypted_data.encode())
            return decrypted_bytes.decode()
        except:
            return None

    def save_to_database(self, data):
        if not self.connect_sql():
            return False

        try:
            cursor = self.connection.cursor()
            query = """
                INSERT INTO users 
                    (id, name, email, phone, created_date, email_valid, phone_valid)
                VALUES 
                    (?, ?, ?, ?, ?, ?, ?)
            """
            for record in data:
                params = (
                    record['id'],
                    record['name'],
                    record['email'],
                    record['phone'],
                    record['created_date'],
                    record['email_valid'],
                    record['phone_valid']
                )
                cursor.execute(query, params)
            self.connection.commit()
            return True
        except Exception as e:
            self.errors.append(f"Database Save Error: {str(e)}")
            return False

    def save_to_file(self, filename, data, format='json'):
        try:
            if format == 'json':
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
            elif format == 'xml':
                root = ET.Element("data")
                for item in data:
                    record = ET.SubElement(root, "record")
                    for key, value in item.items():
                        elem = ET.SubElement(record, key)
                        elem.text = str(value)
                tree = ET.ElementTree(root)
                tree.write(filename)
            self.temp_files.append(filename)
            return True
        except Exception as e:
            self.errors.append(f"File Save Error: {str(e)}")
            return False

    def backup_data(self, data):
        for url in self.backup_urls:
            try:
                backup_data = {
                    'timestamp': datetime.datetime.now().isoformat(),
                    'data': data,
                    'api_key': self.api_key
                }
                print(f"Backing up to {url}")
                return True
            except Exception as e:
                self.errors.append(f"Backup Error for {url}: {str(e)}")
        return False

    def generate_report(self, data):
        report = {
            'total_records': len(data),
            'valid_emails': sum(1 for r in data if r.get('email_valid', False)),
            'valid_phones': sum(1 for r in data if r.get('phone_valid', False)),
            'errors': len(self.errors),
            'generated_at': datetime.datetime.now().isoformat(),
            'generated_by': 'admin'
        }
        return report

    def log_activity(self, action, details):
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'action': action,
            'details': details,
            'user': 'system'
        }
        self.logs.append(log_entry)
        print(f"LOG: {action} - {details}")

    def cleanup_temp_files(self):
        for filename in self.temp_files:
            try:
                if os.path.exists(filename):
                    os.remove(filename)
            except:
                pass
        self.temp_files = []

    def _parse_input_item(self, item):
        if not isinstance(item, str):
            return item
            
        try:
            if item.startswith(('{', '[')):
                return self.parse_json_data(item)
            elif item.startswith('<'):
                return self.parse_xml_data(item)
            else:
                self.log_activity("PARSE_SKIP", f"Skipping invalid input format")
                return None
        except Exception as e:
            self.log_activity("PARSE_ERROR", str(e))
            return None

    def _process_parsed_data(self, parsed_items):
        processed_items = []
        for item in parsed_items:
            if item:
                try:
                    processed = self.process_user_data(item)
                    processed_items.append(processed)
                except Exception as e:
                    self.log_activity("PROCESS_ERROR", f"Error processing item: {str(e)}")
        return processed_items

    def _save_processed_data(self, processed_data, output_file, backup):
        success = True
        
        try:
            if not self.save_to_database(processed_data):
                self.log_activity("DB_ERROR", "Failed to save to database")
                success = False
        except Exception as e:
            self.log_activity("DB_ERROR", str(e))
            success = False

        if output_file:
            try:
                if not self.save_to_file(output_file, processed_data):
                    self.log_activity("FILE_ERROR", f"Failed to save to {output_file}")
                    success = False
            except Exception as e:
                self.log_activity("FILE_ERROR", str(e))
                success = False

        if backup:
            try:
                if not self.backup_data(processed_data):
                    self.log_activity("BACKUP_ERROR", "Failed to backup data")
                    success = False
            except Exception as e:
                self.log_activity("BACKUP_ERROR", str(e))
                success = False

        return success

    def process_everything(self, input_data, output_file=None, backup=True):
        self.log_activity("PROCESS_START", "Starting data processing")

        try:
            parsed_items = [self._parse_input_item(item) for item in input_data]
            parsed_items = [item for item in parsed_items if item is not None]

            if not parsed_items:
                self.log_activity("PROCESS_ERROR", "No valid data to process")
                return {'success': False, 'processed_count': 0, 'errors': self.errors}

            processed_data = self._process_parsed_data(parsed_items)
            
            if not processed_data:
                self.log_activity("PROCESS_ERROR", "No data successfully processed")
                return {'success': False, 'processed_count': 0, 'errors': self.errors}

            save_success = self._save_processed_data(processed_data, output_file, backup)

            report = self.generate_report(processed_data)
            self.log_activity("PROCESS_COMPLETE", f"Processed {len(processed_data)} records")

            return {
                'success': save_success,
                'processed_count': len(processed_data),
                'report': report,
                'errors': self.errors
            }

        except Exception as e:
            self.log_activity("CRITICAL_ERROR", str(e))
            return {
                'success': False,
                'processed_count': 0,
                'errors': self.errors + [str(e)]
            }

    def __del__(self):
        try:
            if self.connection:
                self.connection.close()
            if self.ldap_conn:
                self.ldap_conn.unbind()
            self.cleanup_temp_files()
        except:
            pass
