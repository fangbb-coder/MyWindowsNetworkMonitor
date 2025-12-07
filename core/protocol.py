import struct
from collections import defaultdict

class ProtocolAnalyzer:
    def __init__(self):
        # Protocol port mapping
        self.port_protocol_map = {
            # TCP ports
            80: 'HTTP',
            443: 'HTTPS',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            110: 'POP3',
            143: 'IMAP',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            3389: 'RDP',
            5900: 'VNC',
            # UDP ports
            53: 'DNS',
            67: 'DHCP',
            68: 'DHCP',
            69: 'TFTP',
            123: 'NTP',
            161: 'SNMP',
            162: 'SNMP',
            500: 'IKE',
            4500: 'IPsec',
            1900: 'SSDP',
            5353: 'mDNS'
        }
        
        # Protocol statistics
        self.protocol_stats = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'sessions': set()
        })
    
    def identify_protocol(self, packet_info):
        """Identify the application protocol from packet information"""
        # Check if we already have the protocol identified
        if 'application_protocol' in packet_info:
            return packet_info['application_protocol']
        
        # Get transport protocol and ports
        transport_protocol = packet_info.get('transport_protocol')
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        
        # Default to transport protocol if we can't identify application protocol
        application_protocol = transport_protocol
        
        if transport_protocol == 'TCP':
            application_protocol = self._identify_tcp_protocol(packet_info, src_port, dst_port)
        elif transport_protocol == 'UDP':
            application_protocol = self._identify_udp_protocol(packet_info, src_port, dst_port)
        elif transport_protocol == 'ICMP':
            application_protocol = 'ICMP'
        
        return application_protocol
    
    def _identify_tcp_protocol(self, packet_info, src_port, dst_port):
        """Identify TCP application protocols"""
        # Check well-known ports first
        if dst_port in self.port_protocol_map:
            return self.port_protocol_map[dst_port]
        if src_port in self.port_protocol_map:
            return self.port_protocol_map[src_port]
        
        # Check packet content for protocol signatures
        if 'raw_packet' in packet_info:
            raw_packet = packet_info['raw_packet']
            
            # Extract TCP data (simplified - assuming IPv4)
            if packet_info.get('ip_version') == 4:
                # IPv4 header is typically 20 bytes
                ip_header_len = (raw_packet[14] & 0x0F) * 4
                tcp_header_len = ((raw_packet[14 + ip_header_len + 12] & 0xF0) >> 4) * 4
                data_offset = 14 + ip_header_len + tcp_header_len
                
                if data_offset < len(raw_packet):
                    data = raw_packet[data_offset:]
                    
                    # Check for HTTP
                    if len(data) >= 4:
                        if data.startswith(b'GET ') or data.startswith(b'POST ') or \
                           data.startswith(b'PUT ') or data.startswith(b'DELETE ') or \
                           data.startswith(b'HEAD ') or data.startswith(b'OPTIONS ') or \
                           data.startswith(b'HTTP/'):
                            return 'HTTP'
                    
                    # Check for TLS/HTTPS (ClientHello)
                    if len(data) >= 5:
                        # TLS ClientHello starts with 0x16 0x03 (SSL/TLS record header)
                        if data[0] == 0x16 and (data[1] in [0x03]):
                            return 'HTTPS'
        
        return 'TCP'
    
    def _identify_udp_protocol(self, packet_info, src_port, dst_port):
        """Identify UDP application protocols"""
        # Check well-known ports first
        if dst_port in self.port_protocol_map:
            return self.port_protocol_map[dst_port]
        if src_port in self.port_protocol_map:
            return self.port_protocol_map[src_port]
        
        # Check packet content for DNS
        if src_port == 53 or dst_port == 53:
            if 'raw_packet' in packet_info:
                raw_packet = packet_info['raw_packet']
                
                # Extract UDP data (simplified - assuming IPv4)
                if packet_info.get('ip_version') == 4:
                    # IPv4 header is typically 20 bytes
                    ip_header_len = (raw_packet[14] & 0x0F) * 4
                    udp_header_len = 8
                    data_offset = 14 + ip_header_len + udp_header_len
                    
                    if data_offset < len(raw_packet):
                        data = raw_packet[data_offset:]
                        
                        # DNS packet format: first 2 bytes are transaction ID
                        # Next 2 bytes are flags
                        if len(data) >= 4:
                            # Check if it looks like a DNS packet
                            # We'll just assume it is if it's on port 53
                            return 'DNS'
        
        return 'UDP'
    
    def update_protocol_stats(self, packet_info, application_protocol, session_id):
        """Update protocol statistics"""
        # Update protocol stats
        self.protocol_stats[application_protocol]['packets'] += 1
        self.protocol_stats[application_protocol]['bytes'] += packet_info['length']
        self.protocol_stats[application_protocol]['sessions'].add(session_id)
    
    def get_protocol_stats(self):
        """Get protocol statistics"""
        stats = {}
        for protocol, data in self.protocol_stats.items():
            stats[protocol] = {
                'packets': data['packets'],
                'bytes': data['bytes'],
                'session_count': len(data['sessions'])
            }
        return stats
    
    def get_top_protocols_by_traffic(self, limit=10):
        """Get top protocols by traffic"""
        sorted_protocols = sorted(
            self.protocol_stats.items(),
            key=lambda x: x[1]['bytes'],
            reverse=True
        )
        
        top_protocols = []
        for protocol, data in sorted_protocols[:limit]:
            top_protocols.append({
                'protocol': protocol,
                'bytes': data['bytes'],
                'packets': data['packets'],
                'session_count': len(data['sessions'])
            })
        
        return top_protocols
    
    def get_protocol_distribution(self):
        """Get protocol distribution by traffic"""
        total_bytes = sum(data['bytes'] for data in self.protocol_stats.values())
        if total_bytes == 0:
            return {}
        
        distribution = {}
        for protocol, data in self.protocol_stats.items():
            distribution[protocol] = (data['bytes'] / total_bytes) * 100
        
        return distribution
    
    def reset_stats(self):
        """Reset protocol statistics"""
        self.protocol_stats = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'sessions': set()
        })
    
    def is_encrypted(self, application_protocol):
        """Check if the protocol is encrypted"""
        encrypted_protocols = ['HTTPS', 'SSH', 'FTPS', 'SFTP', 'IMAPS', 'POP3S', 'SMTPS']
        return application_protocol in encrypted_protocols
    
    def get_protocol_info(self, protocol):
        """Get information about a specific protocol"""
        if protocol in self.protocol_stats:
            data = self.protocol_stats[protocol]
            return {
                'packets': data['packets'],
                'bytes': data['bytes'],
                'session_count': len(data['sessions']),
                'encrypted': self.is_encrypted(protocol)
            }
        return None

# Helper functions for protocol analysis
def is_http(packet_data):
    """Check if packet data is HTTP"""
    http_methods = [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'OPTIONS ', b'PATCH ']
    http_versions = [b'HTTP/1.0', b'HTTP/1.1', b'HTTP/2.0']
    
    if len(packet_data) < 4:
        return False
    
    # Check for HTTP methods
    for method in http_methods:
        if packet_data.startswith(method):
            return True
    
    # Check for HTTP versions
    for version in http_versions:
        if version in packet_data[:20]:
            return True
    
    return False

def is_tls(packet_data):
    """Check if packet data is TLS"""
    # TLS record header: 0x16 (Handshake), 0x03 (SSL/TLS version), then version minor
    if len(packet_data) >= 5:
        if packet_data[0] == 0x16 and (packet_data[1] in [0x02, 0x03]):
            return True
    return False

def is_dns(packet_data):
    """Check if packet data is DNS"""
    # DNS packet format check (simplified)
    if len(packet_data) >= 12:
        # DNS header is 12 bytes
        # Check if QR bit is 0 (query) or 1 (response)
        flags = struct.unpack('!H', packet_data[2:4])[0]
        qr = (flags >> 15) & 1
        return qr in [0, 1]
    return False

def get_protocol_name_by_port(port, protocol):
    """Get protocol name by port number"""
    analyzer = ProtocolAnalyzer()
    if port in analyzer.port_protocol_map:
        return analyzer.port_protocol_map[port]
    return protocol
