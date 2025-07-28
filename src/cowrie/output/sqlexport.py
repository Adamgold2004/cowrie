"""
SQL Export Output Module for Cowrie

This module provides enhanced SQL export capabilities with support for multiple databases
and flexible export options.

Configuration:
[output_sqlexport]
enabled = true
database_type = sqlite  # sqlite, mysql, postgresql
export_dir = ${honeypot:log_path}/sql_exports
# SQLite specific
sqlite_file = ${honeypot:log_path}/cowrie_export.db
# MySQL specific (if database_type = mysql)
mysql_host = localhost
mysql_database = cowrie_export
mysql_username = cowrie
mysql_password = secret
mysql_port = 3306
# PostgreSQL specific (if database_type = postgresql)
postgres_host = localhost
postgres_database = cowrie_export
postgres_username = cowrie
postgres_password = secret
postgres_port = 5432
"""

from __future__ import annotations

import os
import sqlite3
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from twisted.internet import defer
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class SQLExportManager:
    """Manages SQL export operations across different database types"""
    
    def __init__(self, database_type: str, export_dir: str, **db_config):
        self.database_type = database_type.lower()
        self.export_dir = export_dir
        self.db_config = db_config
        
        # Ensure export directory exists
        os.makedirs(export_dir, exist_ok=True)
        
        # Initialize database connection
        self.db = None
        self._init_database()
    
    def _init_database(self):
        """Initialize database connection based on type"""
        try:
            if self.database_type == 'sqlite':
                self._init_sqlite()
            elif self.database_type == 'mysql':
                self._init_mysql()
            elif self.database_type == 'postgresql':
                self._init_postgresql()
            else:
                raise ValueError(f"Unsupported database type: {self.database_type}")
        except Exception as e:
            log.err(f"[SQLExport] Failed to initialize {self.database_type} database: {e}")
            raise
    
    def _init_sqlite(self):
        """Initialize SQLite database"""
        db_file = self.db_config.get('sqlite_file', 'cowrie_export.db')
        self.db = sqlite3.connect(db_file, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._create_tables_sqlite()
    
    def _init_mysql(self):
        """Initialize MySQL database"""
        try:
            import mysql.connector
            self.db = mysql.connector.connect(
                host=self.db_config.get('mysql_host', 'localhost'),
                database=self.db_config.get('mysql_database', 'cowrie_export'),
                user=self.db_config.get('mysql_username', 'cowrie'),
                password=self.db_config.get('mysql_password', 'secret'),
                port=self.db_config.get('mysql_port', 3306)
            )
            self._create_tables_mysql()
        except ImportError:
            raise ImportError("mysql-connector-python is required for MySQL export")
    
    def _init_postgresql(self):
        """Initialize PostgreSQL database"""
        try:
            import psycopg2
            import psycopg2.extras
            self.db = psycopg2.connect(
                host=self.db_config.get('postgres_host', 'localhost'),
                database=self.db_config.get('postgres_database', 'cowrie_export'),
                user=self.db_config.get('postgres_username', 'cowrie'),
                password=self.db_config.get('postgres_password', 'secret'),
                port=self.db_config.get('postgres_port', 5432)
            )
            self.db.autocommit = True
            self._create_tables_postgresql()
        except ImportError:
            raise ImportError("psycopg2 is required for PostgreSQL export")
    
    def _create_tables_sqlite(self):
        """Create SQLite tables"""
        cursor = self.db.cursor()
        
        # Sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                starttime DATETIME,
                endtime DATETIME,
                sensor TEXT,
                ip TEXT,
                termsize TEXT,
                client TEXT
            )
        """)
        
        # Events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                eventid TEXT,
                session TEXT,
                timestamp DATETIME,
                message TEXT,
                src_ip TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_port INTEGER,
                data TEXT,
                FOREIGN KEY (session) REFERENCES sessions (id)
            )
        """)
        
        # Auth table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session TEXT,
                success INTEGER,
                username TEXT,
                password TEXT,
                timestamp DATETIME,
                FOREIGN KEY (session) REFERENCES sessions (id)
            )
        """)
        
        # Commands table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session TEXT,
                timestamp DATETIME,
                command TEXT,
                FOREIGN KEY (session) REFERENCES sessions (id)
            )
        """)
        
        # Downloads table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS downloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session TEXT,
                timestamp DATETIME,
                url TEXT,
                outfile TEXT,
                shasum TEXT,
                FOREIGN KEY (session) REFERENCES sessions (id)
            )
        """)
        
        self.db.commit()
    
    def _create_tables_mysql(self):
        """Create MySQL tables"""
        cursor = self.db.cursor()
        
        # Sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id VARCHAR(32) PRIMARY KEY,
                starttime DATETIME,
                endtime DATETIME,
                sensor VARCHAR(255),
                ip VARCHAR(45),
                termsize VARCHAR(16),
                client VARCHAR(255)
            )
        """)
        
        # Events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INT AUTO_INCREMENT PRIMARY KEY,
                eventid VARCHAR(255),
                session VARCHAR(32),
                timestamp DATETIME,
                message TEXT,
                src_ip VARCHAR(45),
                src_port INT,
                dst_ip VARCHAR(45),
                dst_port INT,
                data TEXT,
                FOREIGN KEY (session) REFERENCES sessions (id)
            )
        """)
        
        # Auth table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth (
                id INT AUTO_INCREMENT PRIMARY KEY,
                session VARCHAR(32),
                success BOOLEAN,
                username VARCHAR(255),
                password VARCHAR(255),
                timestamp DATETIME,
                FOREIGN KEY (session) REFERENCES sessions (id)
            )
        """)
        
        # Commands table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS commands (
                id INT AUTO_INCREMENT PRIMARY KEY,
                session VARCHAR(32),
                timestamp DATETIME,
                command TEXT,
                FOREIGN KEY (session) REFERENCES sessions (id)
            )
        """)
        
        # Downloads table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS downloads (
                id INT AUTO_INCREMENT PRIMARY KEY,
                session VARCHAR(32),
                timestamp DATETIME,
                url TEXT,
                outfile VARCHAR(255),
                shasum VARCHAR(64),
                FOREIGN KEY (session) REFERENCES sessions (id)
            )
        """)
        
        self.db.commit()
    
    def _create_tables_postgresql(self):
        """Create PostgreSQL tables"""
        cursor = self.db.cursor()
        
        # Sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id VARCHAR(32) PRIMARY KEY,
                starttime TIMESTAMP,
                endtime TIMESTAMP,
                sensor VARCHAR(255),
                ip INET,
                termsize VARCHAR(16),
                client VARCHAR(255)
            )
        """)
        
        # Events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id SERIAL PRIMARY KEY,
                eventid VARCHAR(255),
                session VARCHAR(32),
                timestamp TIMESTAMP,
                message TEXT,
                src_ip INET,
                src_port INTEGER,
                dst_ip INET,
                dst_port INTEGER,
                data TEXT,
                FOREIGN KEY (session) REFERENCES sessions (id)
            )
        """)
        
        # Auth table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth (
                id SERIAL PRIMARY KEY,
                session VARCHAR(32),
                success BOOLEAN,
                username VARCHAR(255),
                password VARCHAR(255),
                timestamp TIMESTAMP,
                FOREIGN KEY (session) REFERENCES sessions (id)
            )
        """)
        
        # Commands table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS commands (
                id SERIAL PRIMARY KEY,
                session VARCHAR(32),
                timestamp TIMESTAMP,
                command TEXT,
                FOREIGN KEY (session) REFERENCES sessions (id)
            )
        """)
        
        # Downloads table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS downloads (
                id SERIAL PRIMARY KEY,
                session VARCHAR(32),
                timestamp TIMESTAMP,
                url TEXT,
                outfile VARCHAR(255),
                shasum VARCHAR(64),
                FOREIGN KEY (session) REFERENCES sessions (id)
            )
        """)
    
    def store_event(self, event: Dict[str, Any]):
        """Store an event in the database"""
        try:
            cursor = self.db.cursor()
            eventid = event.get('eventid', '')
            session = event.get('session', '')
            timestamp = event.get('timestamp', datetime.now().isoformat())
            
            # Convert timestamp to datetime object if it's a string
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except ValueError:
                    timestamp = datetime.now()
            
            if eventid == 'cowrie.session.connect':
                self._store_session_connect(cursor, event, timestamp)
            elif eventid == 'cowrie.session.closed':
                self._store_session_closed(cursor, event, timestamp)
            elif eventid in ('cowrie.login.success', 'cowrie.login.failed'):
                self._store_auth_attempt(cursor, event, timestamp)
            elif eventid == 'cowrie.command.input':
                self._store_command(cursor, event, timestamp)
            elif eventid == 'cowrie.session.file_download':
                self._store_download(cursor, event, timestamp)
            
            # Store general event
            self._store_general_event(cursor, event, timestamp)
            
            self.db.commit()
            
        except Exception as e:
            log.err(f"[SQLExport] Error storing event: {e}")
            if self.db:
                self.db.rollback()
    
    def _store_session_connect(self, cursor, event, timestamp):
        """Store session connect event"""
        if self.database_type == 'sqlite':
            cursor.execute("""
                INSERT OR REPLACE INTO sessions (id, starttime, sensor, ip, termsize, client)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                event.get('session', ''),
                timestamp,
                event.get('sensor', ''),
                event.get('src_ip', ''),
                event.get('termsize', ''),
                event.get('version', '')
            ))
        elif self.database_type == 'mysql':
            cursor.execute("""
                INSERT INTO sessions (id, starttime, sensor, ip, termsize, client)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE starttime = VALUES(starttime)
            """, (
                event.get('session', ''),
                timestamp,
                event.get('sensor', ''),
                event.get('src_ip', ''),
                event.get('termsize', ''),
                event.get('version', '')
            ))
        elif self.database_type == 'postgresql':
            cursor.execute("""
                INSERT INTO sessions (id, starttime, sensor, ip, termsize, client)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET starttime = EXCLUDED.starttime
            """, (
                event.get('session', ''),
                timestamp,
                event.get('sensor', ''),
                event.get('src_ip', ''),
                event.get('termsize', ''),
                event.get('version', '')
            ))
    
    def _store_session_closed(self, cursor, event, timestamp):
        """Store session closed event"""
        if self.database_type == 'sqlite':
            cursor.execute("""
                UPDATE sessions SET endtime = ? WHERE id = ?
            """, (timestamp, event.get('session', '')))
        else:  # MySQL and PostgreSQL
            cursor.execute("""
                UPDATE sessions SET endtime = %s WHERE id = %s
            """, (timestamp, event.get('session', '')))
    
    def _store_auth_attempt(self, cursor, event, timestamp):
        """Store authentication attempt"""
        success = event.get('eventid') == 'cowrie.login.success'
        
        if self.database_type == 'sqlite':
            cursor.execute("""
                INSERT INTO auth (session, success, username, password, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (
                event.get('session', ''),
                success,
                event.get('username', ''),
                event.get('password', ''),
                timestamp
            ))
        else:  # MySQL and PostgreSQL
            cursor.execute("""
                INSERT INTO auth (session, success, username, password, timestamp)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                event.get('session', ''),
                success,
                event.get('username', ''),
                event.get('password', ''),
                timestamp
            ))
    
    def _store_command(self, cursor, event, timestamp):
        """Store command execution"""
        if self.database_type == 'sqlite':
            cursor.execute("""
                INSERT INTO commands (session, timestamp, command)
                VALUES (?, ?, ?)
            """, (
                event.get('session', ''),
                timestamp,
                event.get('input', '')
            ))
        else:  # MySQL and PostgreSQL
            cursor.execute("""
                INSERT INTO commands (session, timestamp, command)
                VALUES (%s, %s, %s)
            """, (
                event.get('session', ''),
                timestamp,
                event.get('input', '')
            ))
    
    def _store_download(self, cursor, event, timestamp):
        """Store file download"""
        if self.database_type == 'sqlite':
            cursor.execute("""
                INSERT INTO downloads (session, timestamp, url, outfile, shasum)
                VALUES (?, ?, ?, ?, ?)
            """, (
                event.get('session', ''),
                timestamp,
                event.get('url', ''),
                event.get('outfile', ''),
                event.get('shasum', '')
            ))
        else:  # MySQL and PostgreSQL
            cursor.execute("""
                INSERT INTO downloads (session, timestamp, url, outfile, shasum)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                event.get('session', ''),
                timestamp,
                event.get('url', ''),
                event.get('outfile', ''),
                event.get('shasum', '')
            ))
    
    def _store_general_event(self, cursor, event, timestamp):
        """Store general event data"""
        import json
        
        if self.database_type == 'sqlite':
            cursor.execute("""
                INSERT INTO events (eventid, session, timestamp, message, src_ip, src_port, dst_ip, dst_port, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.get('eventid', ''),
                event.get('session', ''),
                timestamp,
                event.get('message', ''),
                event.get('src_ip', ''),
                event.get('src_port'),
                event.get('dst_ip', ''),
                event.get('dst_port'),
                json.dumps(event)
            ))
        else:  # MySQL and PostgreSQL
            cursor.execute("""
                INSERT INTO events (eventid, session, timestamp, message, src_ip, src_port, dst_ip, dst_port, data)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                event.get('eventid', ''),
                event.get('session', ''),
                timestamp,
                event.get('message', ''),
                event.get('src_ip', ''),
                event.get('src_port'),
                event.get('dst_ip', ''),
                event.get('dst_port'),
                json.dumps(event)
            ))

    def export_to_sql_file(self, filename: str, table_names: Optional[List[str]] = None) -> Dict[str, Any]:
        """Export database contents to SQL file"""
        if table_names is None:
            table_names = ['sessions', 'events', 'auth', 'commands', 'downloads']

        filepath = os.path.join(self.export_dir, filename)

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"-- Cowrie Honeypot SQL Export\n")
                f.write(f"-- Generated: {datetime.now().isoformat()}\n")
                f.write(f"-- Database Type: {self.database_type}\n\n")

                cursor = self.db.cursor()

                for table_name in table_names:
                    f.write(f"-- Table: {table_name}\n")

                    # Get table data
                    if self.database_type == 'sqlite':
                        cursor.execute(f"SELECT * FROM {table_name}")
                        rows = cursor.fetchall()

                        if rows:
                            # Get column names
                            cursor.execute(f"PRAGMA table_info({table_name})")
                            columns = [col[1] for col in cursor.fetchall()]

                            for row in rows:
                                values = []
                                for value in row:
                                    if value is None:
                                        values.append('NULL')
                                    elif isinstance(value, str):
                                        values.append(f"'{value.replace(chr(39), chr(39)+chr(39))}'")
                                    else:
                                        values.append(str(value))

                                f.write(f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({', '.join(values)});\n")

                    else:  # MySQL and PostgreSQL
                        cursor.execute(f"SELECT * FROM {table_name}")
                        rows = cursor.fetchall()

                        if rows:
                            # Get column names
                            if self.database_type == 'mysql':
                                cursor.execute(f"SHOW COLUMNS FROM {table_name}")
                                columns = [col[0] for col in cursor.fetchall()]
                            else:  # PostgreSQL
                                cursor.execute(f"""
                                    SELECT column_name FROM information_schema.columns
                                    WHERE table_name = '{table_name}'
                                    ORDER BY ordinal_position
                                """)
                                columns = [col[0] for col in cursor.fetchall()]

                            for row in rows:
                                values = []
                                for value in row:
                                    if value is None:
                                        values.append('NULL')
                                    elif isinstance(value, str):
                                        values.append(f"'{value.replace(chr(39), chr(39)+chr(39))}'")
                                    else:
                                        values.append(str(value))

                                f.write(f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({', '.join(values)});\n")

                    f.write(f"\n")

            return {
                "success": True,
                "filepath": filepath,
                "file_size": os.path.getsize(filepath),
                "tables_exported": table_names
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            cursor = self.db.cursor()
            stats = {}

            tables = ['sessions', 'events', 'auth', 'commands', 'downloads']

            for table in tables:
                if self.database_type == 'sqlite':
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                else:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")

                count = cursor.fetchone()[0]
                stats[f"{table}_count"] = count

            # Get event type distribution
            if self.database_type == 'sqlite':
                cursor.execute("SELECT eventid, COUNT(*) FROM events GROUP BY eventid")
            else:
                cursor.execute("SELECT eventid, COUNT(*) FROM events GROUP BY eventid")

            event_types = dict(cursor.fetchall())
            stats["event_types"] = event_types

            # Get time range
            if self.database_type == 'sqlite':
                cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM events")
            else:
                cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM events")

            time_range = cursor.fetchone()
            if time_range[0] and time_range[1]:
                stats["time_range"] = {
                    "earliest": time_range[0],
                    "latest": time_range[1]
                }

            return stats

        except Exception as e:
            log.err(f"[SQLExport] Error getting statistics: {e}")
            return {}

    def close(self):
        """Close database connection"""
        if self.db:
            self.db.close()


class Output(cowrie.core.output.Output):
    """
    SQL Export output plugin
    """

    def start(self):
        """Initialize the SQL export output"""
        self.database_type = CowrieConfig.get("output_sqlexport", "database_type", fallback="sqlite")
        self.export_dir = CowrieConfig.get("output_sqlexport", "export_dir",
                                          fallback="var/log/cowrie/sql_exports")

        # Database configuration
        db_config = {}

        if self.database_type == 'sqlite':
            db_config['sqlite_file'] = CowrieConfig.get("output_sqlexport", "sqlite_file",
                                                       fallback="var/log/cowrie/cowrie_export.db")
        elif self.database_type == 'mysql':
            db_config.update({
                'mysql_host': CowrieConfig.get("output_sqlexport", "mysql_host", fallback="localhost"),
                'mysql_database': CowrieConfig.get("output_sqlexport", "mysql_database", fallback="cowrie_export"),
                'mysql_username': CowrieConfig.get("output_sqlexport", "mysql_username", fallback="cowrie"),
                'mysql_password': CowrieConfig.get("output_sqlexport", "mysql_password", fallback="secret"),
                'mysql_port': CowrieConfig.getint("output_sqlexport", "mysql_port", fallback=3306)
            })
        elif self.database_type == 'postgresql':
            db_config.update({
                'postgres_host': CowrieConfig.get("output_sqlexport", "postgres_host", fallback="localhost"),
                'postgres_database': CowrieConfig.get("output_sqlexport", "postgres_database", fallback="cowrie_export"),
                'postgres_username': CowrieConfig.get("output_sqlexport", "postgres_username", fallback="cowrie"),
                'postgres_password': CowrieConfig.get("output_sqlexport", "postgres_password", fallback="secret"),
                'postgres_port': CowrieConfig.getint("output_sqlexport", "postgres_port", fallback=5432)
            })

        # Initialize export manager
        try:
            self.export_manager = SQLExportManager(
                database_type=self.database_type,
                export_dir=self.export_dir,
                **db_config
            )
            log.msg(f"[SQLExport] Started with {self.database_type} database")
        except Exception as e:
            log.err(f"[SQLExport] Failed to start: {e}")
            raise

    def stop(self):
        """Stop the SQL export output"""
        if hasattr(self, 'export_manager'):
            # Export final data
            try:
                filename = f"cowrie_final_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
                result = self.export_manager.export_to_sql_file(filename)
                log.msg(f"[SQLExport] Final export: {result}")
            except Exception as e:
                log.err(f"[SQLExport] Final export failed: {e}")

            self.export_manager.close()

    def write(self, event):
        """Process and store events"""
        try:
            if hasattr(self, 'export_manager'):
                self.export_manager.store_event(event)
        except Exception as e:
            log.err(f"[SQLExport] Error writing event: {e}")
