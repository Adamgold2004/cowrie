# Cowrie Web Dashboard

This enhancement adds a comprehensive web-based dashboard to Cowrie honeypot with real-time log viewing and advanced export capabilities.

## Features

### 🌐 Web Dashboard
- **Real-time monitoring**: Live view of honeypot events as they happen
- **Interactive interface**: Modern, responsive web UI with filtering and search
- **Event statistics**: Visual statistics and metrics about honeypot activity
- **Auto-refresh**: Configurable automatic updates every 5 seconds

### 📊 Enhanced JSON Export
- **Advanced filtering**: Filter by event type, time range, source IP, session
- **Structured exports**: Include metadata, statistics, and export information
- **Compression support**: Optional gzip compression for large exports
- **Batch processing**: Automatic export when buffer reaches size limit

### 🗄️ SQL Export & Storage
- **Multi-database support**: SQLite, MySQL, PostgreSQL
- **Structured storage**: Organized tables for sessions, events, auth, commands, downloads
- **SQL file export**: Generate SQL INSERT statements for data migration
- **Real-time storage**: Events stored immediately in structured format

## Installation

### 1. Enable Output Modules

Edit your `cowrie.cfg` file and enable the desired modules:

```ini
# Web Dashboard (required for web interface)
[output_webdashboard]
enabled = true
port = 8080
host = 0.0.0.0
debug = false
max_events = 1000

# Enhanced JSON Export (optional)
[output_jsonexport]
enabled = true
export_dir = ${honeypot:log_path}/exports
compress = true
include_metadata = true
auto_export_hours = 24

# SQL Export (optional)
[output_sqlexport]
enabled = true
database_type = sqlite
export_dir = ${honeypot:log_path}/sql_exports
sqlite_file = ${honeypot:log_path}/cowrie_export.db
```

### 2. Install Dependencies

For MySQL support:
```bash
pip install mysql-connector-python
```

For PostgreSQL support:
```bash
pip install psycopg2-binary
```

### 3. Start Cowrie

Start Cowrie normally. The web dashboard will be available at:
- **Default**: http://localhost:8080
- **Custom**: http://your-server:port (based on your configuration)

## Usage

### Web Dashboard

1. **Access the dashboard**: Open your browser and navigate to the configured URL
2. **View events**: See real-time events in the main events list
3. **Filter events**: Use the dropdown to filter by event type
4. **Export data**: Click "Export JSON" or "Export SQL" buttons
5. **Monitor statistics**: View live statistics in the dashboard cards

### API Endpoints

The web dashboard provides REST API endpoints:

- `GET /api/events` - Get events list
  - Parameters: `type`, `limit`, `since`
- `GET /api/stats` - Get statistics
- `GET /api/export` - Export data
  - Parameters: `format` (json|sql)

### Export Capabilities

#### JSON Export
- **Manual export**: Use web interface or API
- **Automatic export**: Configure `auto_export_hours` for scheduled exports
- **Filtered export**: Export specific event types, time ranges, or source IPs

#### SQL Export
- **Database storage**: Events stored in structured tables
- **SQL file export**: Generate portable SQL INSERT statements
- **Multi-database**: Support for SQLite, MySQL, PostgreSQL

## Configuration Reference

### Web Dashboard Options

```ini
[output_webdashboard]
enabled = false          # Enable/disable the module
port = 8080             # Web server port
host = 0.0.0.0          # Bind address (0.0.0.0 for all interfaces)
debug = false           # Enable debug logging
max_events = 1000       # Maximum events to keep in memory
```

### JSON Export Options

```ini
[output_jsonexport]
enabled = false                    # Enable/disable the module
logfile = cowrie_export.json      # Regular JSON log file (optional)
export_dir = exports               # Directory for export files
compress = true                    # Compress export files with gzip
include_metadata = true            # Include export metadata
filter_events =                    # Filter specific events (comma-separated)
auto_export_hours = 0              # Auto-export interval (0 = disabled)
max_buffer_size = 10000           # Buffer size before auto-export
```

### SQL Export Options

```ini
[output_sqlexport]
enabled = false                    # Enable/disable the module
database_type = sqlite             # Database type: sqlite, mysql, postgresql
export_dir = sql_exports           # Directory for SQL export files

# SQLite configuration
sqlite_file = cowrie_export.db

# MySQL configuration (if database_type = mysql)
mysql_host = localhost
mysql_database = cowrie_export
mysql_username = cowrie
mysql_password = secret
mysql_port = 3306

# PostgreSQL configuration (if database_type = postgresql)
postgres_host = localhost
postgres_database = cowrie_export
postgres_username = cowrie
postgres_password = secret
postgres_port = 5432
```

## Testing

A test script is provided to verify the installation:

```bash
python test_web_dashboard.py
```

This will:
1. Create a test configuration
2. Start all output modules
3. Generate test events
4. Test web interface and API endpoints
5. Verify export functionality

## Security Considerations

- **Network access**: The web dashboard binds to the configured host/port
- **Authentication**: No built-in authentication - use reverse proxy if needed
- **Firewall**: Ensure the dashboard port is properly firewalled
- **HTTPS**: Use a reverse proxy (nginx, Apache) for HTTPS termination

## Troubleshooting

### Common Issues

1. **Port already in use**: Change the port in configuration
2. **Permission denied**: Ensure Cowrie has write access to export directories
3. **Database connection failed**: Check database credentials and connectivity
4. **Module not loading**: Verify the module files are in the correct location

### Debug Mode

Enable debug mode for detailed logging:

```ini
[output_webdashboard]
debug = true
```

### Log Files

Check Cowrie logs for error messages:
```bash
tail -f var/log/cowrie/cowrie.log
```

## File Structure

```
src/cowrie/output/
├── webdashboard.py     # Web dashboard output module
├── jsonexport.py       # Enhanced JSON export module
└── sqlexport.py        # SQL export module

etc/
└── cowrie.cfg.dist     # Updated configuration template

test_web_dashboard.py   # Test script
WEB_DASHBOARD_README.md # This documentation
```

## API Documentation

### Events API

**GET /api/events**

Parameters:
- `type` (optional): Filter by event type
- `limit` (optional): Maximum number of events to return
- `since` (optional): Return events after this timestamp

Response:
```json
{
  "success": true,
  "events": [...],
  "total": 150
}
```

### Statistics API

**GET /api/stats**

Response:
```json
{
  "success": true,
  "stats": {
    "total_events": 150,
    "event_types": {
      "cowrie.session.connect": 25,
      "cowrie.login.failed": 45,
      "cowrie.command.input": 80
    }
  }
}
```

### Export API

**GET /api/export**

Parameters:
- `format`: Export format (`json` or `sql`)
- Additional filtering parameters supported

Response: File download with appropriate content-type

## Contributing

When contributing to the web dashboard:

1. Follow existing code style and patterns
2. Add appropriate error handling and logging
3. Update configuration documentation
4. Test with multiple browsers and scenarios
5. Consider security implications of changes

## License

This enhancement follows the same license as the main Cowrie project.
