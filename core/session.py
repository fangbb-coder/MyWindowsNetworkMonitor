import time
import socket
from datetime import datetime
from collections import defaultdict
import psutil
from .process import get_connection_to_pid_map, get_process_path, get_process_name
# 尝试导入GeoLite2查询模块
try:
    from .geolite2 import geolite2_locator
    HAS_GEOLITE2 = True
except ImportError:
    # 回退到原来的geoip模块
    from .geoip import geoip
    HAS_GEOLITE2 = False

class Session:
    def __init__(self, protocol, src_ip, src_port, dst_ip, dst_port):
        self.protocol = protocol
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        
        # Session identification
        self.id = f"{protocol}_{src_ip}:{src_port}_{dst_ip}:{dst_port}"
        
        # Traffic statistics
        self.packets_sent = 0
        self.packets_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        
        # Session timing
        self.start_time = datetime.now()
        self.last_activity = self.start_time
        self.duration = 0
        
        # Process information
        self.pid = None
        self.process_name = '未知'
        self.process_path = None
        
        # Location info
        self.location = "Pending..."
        
        # Protocol information
        self.application_protocol = None
        
        # State information (for TCP)
        self.state = "ESTABLISHED" if protocol == "TCP" else "ACTIVE"
    
    def update(self, packet_info, is_outgoing):
        """Update the session with a new packet"""
        # Update last activity time
        self.last_activity = datetime.now()
        self.duration = (self.last_activity - self.start_time).total_seconds()
        
        # Update packet and byte counts
        if is_outgoing:
            self.packets_sent += 1
            self.bytes_sent += packet_info.get('length', 0)
        else:
            self.packets_received += 1
            self.bytes_received += packet_info.get('length', 0)
            
        # Trigger location lookup if not set
        if self.location == "Pending..." or self.location == "Unknown":
             # Determine remote IP
            remote_ip = self.dst_ip if is_outgoing else self.src_ip
            
            # 使用GeoLite2查询地理位置
            if HAS_GEOLITE2:
                location_data = geolite2_locator.get_location(remote_ip)
                if location_data:
                    # 格式化地理位置信息
                    if location_data['country'] == '本地' or location_data['country'] == '本地网络':
                        self.location = '本地网络'
                    elif location_data['lat'] is not None and location_data['lon'] is not None:
                        # 构造包含经纬度的位置信息
                        location_parts = []
                        if location_data['city'] and location_data['city'] != '未知':
                            location_parts.append(location_data['city'])
                        if location_data['region'] and location_data['region'] != '未知':
                            location_parts.append(location_data['region'])
                        if location_data['country'] and location_data['country'] != '未知':
                            location_parts.append(location_data['country'])
                        
                        self.location = ' · '.join(location_parts) if location_parts else '未知'
                    else:
                        self.location = '未知'
                else:
                    self.location = '未知'
            else:
                # 回退到原来的geoip模块
                self.location = geoip.get_location(remote_ip)

    def update_process_info(self, pid):
        """Update the process information for this session"""
        if self.pid != pid:
            self.pid = pid
            self.process_name = get_process_name(pid)
            self.process_path = get_process_path(pid)
    
    def update_application_protocol(self, protocol):
        """Update the application protocol for this session"""
        self.application_protocol = protocol
    
    def update_state(self, state):
        """Update the session state (for TCP)"""
        self.state = state
    
    def to_dict(self):
        """Convert session to a dictionary for serialization"""
        return {
            'id': self.id,
            'protocol': self.protocol,
            'src_ip': self.src_ip,
            'src_port': self.src_port,
            'dst_ip': self.dst_ip,
            'dst_port': self.dst_port,
            'packets_sent': self.packets_sent,
            'packets_received': self.packets_received,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'total_bytes': self.bytes_sent + self.bytes_received,
            'start_time': self.start_time.isoformat(),
            'last_activity': self.last_activity.isoformat(),
            'duration': round(self.duration, 2),
            'pid': self.pid,
            'process_name': self.process_name,
            'process_path': self.process_path,
            'location': self.location,
            'application_protocol': self.application_protocol,
            'state': self.state
        }

class SessionManager:
    def __init__(self, cleanup_interval=60):
        self.sessions = {}
        self.process_map = {}
        self.cleanup_interval = cleanup_interval
        self.last_cleanup = time.time()
        
        # Traffic statistics
        self.total_traffic = {
            'bytes_sent': 0,
            'bytes_received': 0,
            'packets_sent': 0,
            'packets_received': 0
        }
    
    def get_session_key(self, packet_info):
        """Generate a session key from packet information"""
        protocol = packet_info.get('transport_protocol', 'UNKNOWN')
        src_ip = packet_info.get('src_ip', '0.0.0.0')
        src_port = packet_info.get('src_port', 0)
        dst_ip = packet_info.get('dst_ip', '0.0.0.0')
        dst_port = packet_info.get('dst_port', 0)
        
        # For TCP and UDP, use the full five-tuple
        return (protocol, src_ip, src_port, dst_ip, dst_port)
    
    def get_reverse_session_key(self, packet_info):
        """Generate a reverse session key (for incoming packets)"""
        protocol = packet_info.get('transport_protocol', 'UNKNOWN')
        src_ip = packet_info.get('src_ip', '0.0.0.0')
        src_port = packet_info.get('src_port', 0)
        dst_ip = packet_info.get('dst_ip', '0.0.0.0')
        dst_port = packet_info.get('dst_port', 0)
        
        # Reverse source and destination
        return (protocol, dst_ip, dst_port, src_ip, src_port)
    
    def update_process_map(self):
        """Update the connection to PID mapping"""
        self.process_map = get_connection_to_pid_map()
    
    def _get_local_ips(self):
        """Get a set of local IP addresses"""
        try:
            import psutil
            local_ips = set()
            addrs = psutil.net_if_addrs()
            for interface_name, interface_addrs in addrs.items():
                for addr in interface_addrs:
                    # Skip loopback and non-IPv4 addresses
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        local_ips.add(addr.address)
            return local_ips
        except Exception:
            # Fallback to common local IP ranges
            return {'10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'}
    
    def get_pid_for_session(self, session_key):
        """Get the PID for a given session key"""
        protocol, src_ip, src_port, dst_ip, dst_port = session_key
        
        # Try to find the PID in process map
        if protocol in ['TCP', 'TCPv6']:
            # For TCP, use the full five-tuple
            conn_key = (protocol, src_ip, src_port, dst_ip, dst_port)
            if conn_key in self.process_map:
                return self.process_map[conn_key]
            
            # Try the reverse direction
            conn_key = (protocol, dst_ip, dst_port, src_ip, src_port)
            if conn_key in self.process_map:
                return self.process_map[conn_key]
        elif protocol in ['UDP', 'UDPv6']:
            # For UDP, use local address and port
            conn_key = (protocol, src_ip, src_port)
            if conn_key in self.process_map:
                return self.process_map[conn_key]
            
            # Try the reverse direction
            conn_key = (protocol, dst_ip, dst_port)
            if conn_key in self.process_map:
                return self.process_map[conn_key]
        
        return None
    
    def process_packet(self, packet_info):
        """Process a packet and update the corresponding session"""
        # Skip packets without transport protocol
        if 'transport_protocol' not in packet_info:
            return None
        
        # Generate session keys
        session_key = self.get_session_key(packet_info)
        reverse_key = self.get_reverse_session_key(packet_info)
        
        # Get local IP addresses for determining direction
        local_ips = self._get_local_ips()
        
        # Determine if packet is outgoing or incoming
        src_ip = packet_info.get('src_ip', '')
        dst_ip = packet_info.get('dst_ip', '')
        
        # Check if source is local IP (outgoing) or destination is local IP (incoming)
        is_outgoing = src_ip in local_ips and dst_ip not in local_ips
        is_incoming = dst_ip in local_ips and src_ip not in local_ips
        
        # If both IPs are local or both are external, default to outgoing
        if not (is_outgoing or is_incoming):
            is_outgoing = True
            is_incoming = False
        
        # Check if session exists
        if session_key in self.sessions:
            session = self.sessions[session_key]
        elif reverse_key in self.sessions:
            session = self.sessions[reverse_key]
            is_outgoing = is_incoming  # Flip direction if we found reverse session
        else:
            # Create a new session - ensure protocol name is uppercase
            protocol = packet_info.get('transport_protocol', 'UNKNOWN').upper()
            src_port = packet_info.get('src_port', 0)
            dst_port = packet_info.get('dst_port', 0)
            session = Session(protocol, src_ip, src_port, dst_ip, dst_port)
            self.sessions[session_key] = session
        
        # Update the session with the new packet
        session.update(packet_info, is_outgoing)
        
        # Update process information if needed
        if session.pid is None or session.process_name == 'unknown' or session.process_name == '未知':
            # Only update map if we really need to (expensive)
            # We can use a simple counter or time check to limit updates
            if not hasattr(self, '_last_map_update') or time.time() - self._last_map_update > 1.0:
                self.update_process_map()
                self._last_map_update = time.time()
            
            pid = self.get_pid_for_session(session_key)
            if pid:
                session.update_process_info(pid)
            else:
                # Try reverse key as fallback for PID lookup
                pid = self.get_pid_for_session(reverse_key)
                if pid:
                     session.update_process_info(pid)
        
        # Update total traffic statistics
        if is_outgoing:
            self.total_traffic['bytes_sent'] += packet_info.get('length', 0)
            self.total_traffic['packets_sent'] += 1
        else:
            self.total_traffic['bytes_received'] += packet_info.get('length', 0)
            self.total_traffic['packets_received'] += 1
        
        return session
    
    def cleanup_old_sessions(self, inactive_timeout=300):
        """Clean up inactive sessions"""
        current_time = time.time()
        
        # Only cleanup if interval has passed
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        self.last_cleanup = current_time
        
        # Find sessions that are inactive
        inactive_sessions = []
        for session_key, session in self.sessions.items():
            inactive_time = (current_time - session.last_activity.timestamp())
            if inactive_time > inactive_timeout:
                inactive_sessions.append(session_key)
        
        # Remove inactive sessions
        for session_key in inactive_sessions:
            del self.sessions[session_key]
    
    def get_all_sessions(self):
        """Get all active sessions"""
        return list(self.sessions.values())
    
    def get_sessions_by_process(self, pid):
        """Get all sessions for a specific process"""
        return [session for session in self.sessions.values() if session.pid == pid]
    
    def get_sessions_by_protocol(self, protocol):
        """Get all sessions for a specific protocol"""
        return [session for session in self.sessions.values() if session.protocol == protocol]
    
    def get_sessions_by_ip(self, ip):
        """Get all sessions involving a specific IP"""
        return [session for session in self.sessions.values() 
                if session.src_ip == ip or session.dst_ip == ip]
    
    def get_session_stats(self):
        """Get overall session statistics"""
        return {
            'total_sessions': len(self.sessions),
            'tcp_sessions': len(self.get_sessions_by_protocol('TCP')),
            'udp_sessions': len(self.get_sessions_by_protocol('UDP')),
            'total_traffic': self.total_traffic
        }
    
    def get_top_sessions_by_traffic(self, limit=10):
        """Get the top sessions by total traffic"""
        sessions = sorted(
            self.sessions.values(),
            key=lambda s: s.bytes_sent + s.bytes_received,
            reverse=True
        )
        return sessions[:limit]
    
    def get_top_processes_by_traffic(self, limit=10):
        """Get the top processes by total traffic"""
        # Group sessions by process
        process_traffic = defaultdict(lambda: {'bytes_sent': 0, 'bytes_received': 0, 'sessions': 0})
        
        for session in self.sessions.values():
            if session.pid:
                process_traffic[session.pid]['bytes_sent'] += session.bytes_sent
                process_traffic[session.pid]['bytes_received'] += session.bytes_received
                process_traffic[session.pid]['sessions'] += 1
        
        # Convert to list and sort
        top_processes = []
        for pid, stats in process_traffic.items():
            process_name = get_process_name(pid)
            process_path = get_process_path(pid)
            top_processes.append({
                'pid': pid,
                'process_name': process_name,
                'process_path': process_path,
                'bytes_sent': stats['bytes_sent'],
                'bytes_received': stats['bytes_received'],
                'total_bytes': stats['bytes_sent'] + stats['bytes_received'],
                'sessions': stats['sessions']
            })
        
        # Sort by total traffic
        top_processes.sort(key=lambda p: p['total_bytes'], reverse=True)
        
        return top_processes[:limit]