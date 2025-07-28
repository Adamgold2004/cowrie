"""
Enhanced JSON Export Output Module for Cowrie

This module extends the basic JSON logging with advanced export capabilities:
- Filtering by event type, time range, source IP
- Structured export with metadata
- Compression support
- Custom formatting options

Configuration:
[output_jsonexport]
enabled = true
logfile = ${honeypot:log_path}/cowrie_export.json
export_dir = ${honeypot:log_path}/exports
max_file_size = 100MB
compress = true
include_metadata = true
filter_events = cowrie.session.connect,cowrie.login.success,cowrie.command.input
"""

from __future__ import annotations

import gzip
import json
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from twisted.python import log

import cowrie.core.output
import cowrie.python.logfile
from cowrie.core.config import CowrieConfig


class JSONExportManager:
    """Manages JSON export operations with filtering and formatting"""
    
    def __init__(self, export_dir: str, compress: bool = True, include_metadata: bool = True):
        self.export_dir = export_dir
        self.compress = compress
        self.include_metadata = include_metadata
        self.events_buffer: List[Dict[str, Any]] = []
        self.stats = defaultdict(int)
        
        # Ensure export directory exists
        os.makedirs(export_dir, exist_ok=True)
    
    def add_event(self, event: Dict[str, Any]) -> None:
        """Add an event to the export buffer"""
        # Clean up the event (remove twisted legacy keys)
        cleaned_event = {}
        for key, value in event.items():
            if not key.startswith("log_") and key not in ("time", "system"):
                cleaned_event[key] = value
        
        # Add processing timestamp
        cleaned_event["processed_at"] = time.time()
        
        self.events_buffer.append(cleaned_event)
        self.stats[cleaned_event.get("eventid", "unknown")] += 1
        self.stats["total_events"] += 1
    
    def export_filtered(self, 
                       filename: str,
                       event_types: Optional[Set[str]] = None,
                       start_time: Optional[float] = None,
                       end_time: Optional[float] = None,
                       source_ips: Optional[Set[str]] = None,
                       sessions: Optional[Set[str]] = None) -> Dict[str, Any]:
        """Export events with filtering options"""
        
        filtered_events = []
        
        for event in self.events_buffer:
            # Filter by event type
            if event_types and event.get("eventid") not in event_types:
                continue
            
            # Filter by time range
            event_time = event.get("timestamp")
            if event_time:
                try:
                    # Handle different timestamp formats
                    if isinstance(event_time, str):
                        event_timestamp = datetime.fromisoformat(event_time.replace('Z', '+00:00')).timestamp()
                    else:
                        event_timestamp = float(event_time)
                    
                    if start_time and event_timestamp < start_time:
                        continue
                    if end_time and event_timestamp > end_time:
                        continue
                except (ValueError, TypeError):
                    pass  # Skip time filtering if timestamp is invalid
            
            # Filter by source IP
            if source_ips and event.get("src_ip") not in source_ips:
                continue
            
            # Filter by session
            if sessions and event.get("session") not in sessions:
                continue
            
            filtered_events.append(event)
        
        # Create export data structure
        export_data = {
            "export_info": {
                "timestamp": time.time(),
                "date": datetime.now().isoformat(),
                "total_events": len(filtered_events),
                "filters_applied": {
                    "event_types": list(event_types) if event_types else None,
                    "start_time": start_time,
                    "end_time": end_time,
                    "source_ips": list(source_ips) if source_ips else None,
                    "sessions": list(sessions) if sessions else None
                }
            } if self.include_metadata else {},
            "events": filtered_events
        }
        
        # Add statistics if metadata is enabled
        if self.include_metadata:
            filtered_stats = defaultdict(int)
            for event in filtered_events:
                filtered_stats[event.get("eventid", "unknown")] += 1
            export_data["export_info"]["event_statistics"] = dict(filtered_stats)
        
        # Write to file
        filepath = os.path.join(self.export_dir, filename)
        
        if self.compress and not filename.endswith('.gz'):
            filepath += '.gz'
            with gzip.open(filepath, 'wt', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
        else:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
        
        return {
            "success": True,
            "filepath": filepath,
            "events_exported": len(filtered_events),
            "file_size": os.path.getsize(filepath)
        }
    
    def export_by_timerange(self, hours: int = 24) -> Dict[str, Any]:
        """Export events from the last N hours"""
        end_time = time.time()
        start_time = end_time - (hours * 3600)
        
        filename = f"cowrie_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hours}h.json"
        
        return self.export_filtered(
            filename=filename,
            start_time=start_time,
            end_time=end_time
        )
    
    def export_by_event_type(self, event_types: List[str]) -> Dict[str, Any]:
        """Export events of specific types"""
        filename = f"cowrie_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{'_'.join(event_types)}.json"
        
        return self.export_filtered(
            filename=filename,
            event_types=set(event_types)
        )
    
    def export_by_source_ip(self, source_ips: List[str]) -> Dict[str, Any]:
        """Export events from specific source IPs"""
        filename = f"cowrie_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}_ips.json"
        
        return self.export_filtered(
            filename=filename,
            source_ips=set(source_ips)
        )
    
    def get_export_stats(self) -> Dict[str, Any]:
        """Get statistics about the current export buffer"""
        if not self.events_buffer:
            return {"total_events": 0, "event_types": {}, "time_range": None}
        
        # Calculate time range
        timestamps = []
        for event in self.events_buffer:
            event_time = event.get("timestamp")
            if event_time:
                try:
                    if isinstance(event_time, str):
                        timestamps.append(datetime.fromisoformat(event_time.replace('Z', '+00:00')).timestamp())
                    else:
                        timestamps.append(float(event_time))
                except (ValueError, TypeError):
                    pass
        
        time_range = None
        if timestamps:
            time_range = {
                "earliest": min(timestamps),
                "latest": max(timestamps),
                "span_hours": (max(timestamps) - min(timestamps)) / 3600
            }
        
        return {
            "total_events": len(self.events_buffer),
            "event_types": dict(self.stats),
            "time_range": time_range,
            "buffer_size_mb": sum(len(str(event)) for event in self.events_buffer) / (1024 * 1024)
        }
    
    def clear_buffer(self) -> None:
        """Clear the events buffer"""
        self.events_buffer.clear()
        self.stats.clear()


class Output(cowrie.core.output.Output):
    """
    Enhanced JSON export output plugin
    """
    
    def start(self):
        """Initialize the JSON export output"""
        # Basic configuration
        self.logfile = CowrieConfig.get("output_jsonexport", "logfile", 
                                       fallback="var/log/cowrie/cowrie_export.json")
        self.export_dir = CowrieConfig.get("output_jsonexport", "export_dir", 
                                          fallback="var/log/cowrie/exports")
        self.compress = CowrieConfig.getboolean("output_jsonexport", "compress", fallback=True)
        self.include_metadata = CowrieConfig.getboolean("output_jsonexport", "include_metadata", 
                                                        fallback=True)
        
        # Event filtering
        filter_events_str = CowrieConfig.get("output_jsonexport", "filter_events", fallback="")
        self.filter_events = set(filter_events_str.split(",")) if filter_events_str else None
        
        # Auto-export configuration
        self.auto_export_hours = CowrieConfig.getint("output_jsonexport", "auto_export_hours", 
                                                     fallback=0)  # 0 = disabled
        self.max_buffer_size = CowrieConfig.getint("output_jsonexport", "max_buffer_size", 
                                                   fallback=10000)
        
        # Initialize export manager
        self.export_manager = JSONExportManager(
            export_dir=self.export_dir,
            compress=self.compress,
            include_metadata=self.include_metadata
        )
        
        # Initialize regular JSON logging if logfile is specified
        if self.logfile:
            dirs = os.path.dirname(self.logfile)
            base = os.path.basename(self.logfile)
            self.outfile = cowrie.python.logfile.CowrieDailyLogFile(
                base, dirs, defaultMode=0o664
            )
        else:
            self.outfile = None
        
        # Setup auto-export timer if enabled
        if self.auto_export_hours > 0:
            from twisted.internet import reactor
            self.auto_export_timer = reactor.callLater(
                self.auto_export_hours * 3600, 
                self._auto_export
            )
        
        log.msg(f"[JSONExport] Started with export directory: {self.export_dir}")
    
    def stop(self):
        """Stop the JSON export output"""
        if hasattr(self, 'auto_export_timer'):
            self.auto_export_timer.cancel()
        
        if self.outfile:
            self.outfile.flush()
        
        # Export remaining events
        if self.export_manager.events_buffer:
            result = self.export_manager.export_by_timerange(hours=24)
            log.msg(f"[JSONExport] Final export: {result}")
    
    def write(self, event):
        """Process and export events"""
        try:
            # Filter events if configured
            if self.filter_events and event.get("eventid") not in self.filter_events:
                return
            
            # Add to export manager
            self.export_manager.add_event(event)
            
            # Write to regular log file if configured
            if self.outfile:
                # Clean event for JSON serialization
                clean_event = {}
                for key, value in event.items():
                    if not key.startswith("log_") and key not in ("time", "system"):
                        clean_event[key] = value
                
                try:
                    json.dump(clean_event, self.outfile, separators=(",", ":"), default=str)
                    self.outfile.write("\n")
                    self.outfile.flush()
                except TypeError as e:
                    log.err(f"[JSONExport] Can't serialize event: {e}")
            
            # Check if buffer is getting too large
            if len(self.export_manager.events_buffer) >= self.max_buffer_size:
                result = self.export_manager.export_by_timerange(hours=24)
                log.msg(f"[JSONExport] Buffer full, auto-exported: {result}")
                self.export_manager.clear_buffer()
                
        except Exception as e:
            log.err(f"[JSONExport] Error processing event: {e}")
    
    def _auto_export(self):
        """Perform automatic export"""
        try:
            result = self.export_manager.export_by_timerange(hours=self.auto_export_hours)
            log.msg(f"[JSONExport] Auto-export completed: {result}")
            
            # Schedule next auto-export
            from twisted.internet import reactor
            self.auto_export_timer = reactor.callLater(
                self.auto_export_hours * 3600, 
                self._auto_export
            )
        except Exception as e:
            log.err(f"[JSONExport] Auto-export failed: {e}")
