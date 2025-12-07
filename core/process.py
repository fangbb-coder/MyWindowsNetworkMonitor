import ctypes
import socket
import struct
import psutil
from ctypes import wintypes

# Windows API constants
AF_INET = 2
AF_INET6 = 23
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID_ALL = 1

# Windows API structures
class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]

class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]

class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("LocalAddr", wintypes.BYTE * 16),
        ("dwLocalScopeId", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("RemoteAddr", wintypes.BYTE * 16),
        ("dwRemoteScopeId", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwState", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]

class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("LocalAddr", wintypes.BYTE * 16),
        ("dwLocalScopeId", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]

# Load Windows DLLs
iphlpapi = ctypes.WinDLL("iphlpapi.dll")
kernel32 = ctypes.WinDLL("kernel32.dll")
psapi = ctypes.WinDLL("psapi.dll")

# Windows API functions
get_extended_tcp_table = iphlpapi.GetExtendedTcpTable
get_extended_udp_table = iphlpapi.GetExtendedUdpTable
get_extended_tcpv6_table = iphlpapi.GetExtendedTcpTable
# Note: GetExtendedTcpTable handles both IPv4 and IPv6 with different parameters
get_extended_udpv6_table = iphlpapi.GetExtendedUdpTable
# Note: GetExtendedUdpTable handles both IPv4 and IPv6 with different parameters
get_process_image_file_name = psapi.GetProcessImageFileNameA
open_process = kernel32.OpenProcess

# Process access rights
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# TCP states mapping
tcp_states = {
    1: "CLOSED",
    2: "LISTENING",
    3: "SYN_SENT",
    4: "SYN_RCVD",
    5: "ESTABLISHED",
    6: "FIN_WAIT_1",
    7: "FIN_WAIT_2",
    8: "CLOSE_WAIT",
    9: "CLOSING",
    10: "LAST_ACK",
    11: "TIME_WAIT",
    12: "DELETE_TCB"
}

def _ntohs(port):
    """Convert network byte order to host byte order for ports"""
    return ctypes.windll.ws2_32.ntohs(port)

def _inet_ntoa(addr):
    """Convert DWORD IP address to string"""
    return socket.inet_ntoa(struct.pack("!I", addr))

def _inet_ntop(addr_bytes):
    """Convert IPv6 address bytes to string"""
    return socket.inet_ntop(AF_INET6, bytes(addr_bytes))

def get_tcp_connections():
    """Get all TCP connections with their owning PIDs"""
    connections = []
    
    # First call to get required buffer size
    buffer_size = wintypes.DWORD()
    result = get_extended_tcp_table(
        None,
        ctypes.byref(buffer_size),
        True,
        AF_INET,
        TCP_TABLE_OWNER_PID_ALL,
        0
    )
    
    # Allocate buffer and make second call
    buffer = ctypes.create_string_buffer(buffer_size.value)
    result = get_extended_tcp_table(
        buffer,
        ctypes.byref(buffer_size),
        True,
        AF_INET,
        TCP_TABLE_OWNER_PID_ALL,
        0
    )
    
    if result != 0:
        return connections
    
    # Parse the buffer
    num_entries = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD))[0]
    rows = ctypes.cast(
        ctypes.addressof(buffer) + ctypes.sizeof(wintypes.DWORD),
        ctypes.POINTER(MIB_TCPROW_OWNER_PID)
    )
    
    for i in range(num_entries):
        row = rows[i]
        local_addr = _inet_ntoa(row.dwLocalAddr)
        local_port = _ntohs(row.dwLocalPort)
        remote_addr = _inet_ntoa(row.dwRemoteAddr)
        remote_port = _ntohs(row.dwRemotePort)
        state = tcp_states.get(row.dwState, "UNKNOWN")
        
        connections.append({
            "protocol": "TCP",
            "local_addr": local_addr,
            "local_port": local_port,
            "remote_addr": remote_addr,
            "remote_port": remote_port,
            "state": state,
            "pid": row.dwOwningPid
        })
    
    return connections

def get_udp_connections():
    """Get all UDP connections with their owning PIDs"""
    connections = []
    
    # First call to get required buffer size
    buffer_size = wintypes.DWORD()
    result = get_extended_udp_table(
        None,
        ctypes.byref(buffer_size),
        True,
        AF_INET,
        UDP_TABLE_OWNER_PID_ALL,
        0
    )
    
    # Allocate buffer and make second call
    buffer = ctypes.create_string_buffer(buffer_size.value)
    result = get_extended_udp_table(
        buffer,
        ctypes.byref(buffer_size),
        True,
        AF_INET,
        UDP_TABLE_OWNER_PID_ALL,
        0
    )
    
    if result != 0:
        return connections
    
    # Parse the buffer
    num_entries = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD))[0]
    rows = ctypes.cast(
        ctypes.addressof(buffer) + ctypes.sizeof(wintypes.DWORD),
        ctypes.POINTER(MIB_UDPROW_OWNER_PID)
    )
    
    for i in range(num_entries):
        row = rows[i]
        local_addr = _inet_ntoa(row.dwLocalAddr)
        local_port = _ntohs(row.dwLocalPort)
        
        connections.append({
            "protocol": "UDP",
            "local_addr": local_addr,
            "local_port": local_port,
            "remote_addr": "0.0.0.0",
            "remote_port": 0,
            "state": "LISTENING",
            "pid": row.dwOwningPid
        })
    
    return connections

def get_tcpv6_connections():
    """Get all TCPv6 connections with their owning PIDs"""
    connections = []
    
    # First call to get required buffer size
    buffer_size = wintypes.DWORD()
    result = get_extended_tcpv6_table(
        None,
        ctypes.byref(buffer_size),
        True,
        AF_INET6,
        TCP_TABLE_OWNER_PID_ALL,
        0
    )
    
    # Allocate buffer and make second call
    buffer = ctypes.create_string_buffer(buffer_size.value)
    result = get_extended_tcpv6_table(
        buffer,
        ctypes.byref(buffer_size),
        True,
        AF_INET6,
        TCP_TABLE_OWNER_PID_ALL,
        0
    )
    
    if result != 0:
        return connections
    
    # Parse the buffer
    num_entries = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD))[0]
    rows = ctypes.cast(
        ctypes.addressof(buffer) + ctypes.sizeof(wintypes.DWORD),
        ctypes.POINTER(MIB_TCP6ROW_OWNER_PID)
    )
    
    for i in range(num_entries):
        row = rows[i]
        local_addr = _inet_ntop(row.LocalAddr)
        local_port = _ntohs(row.dwLocalPort)
        remote_addr = _inet_ntop(row.RemoteAddr)
        remote_port = _ntohs(row.dwRemotePort)
        state = tcp_states.get(row.dwState, "UNKNOWN")
        
        connections.append({
            "protocol": "TCPv6",
            "local_addr": local_addr,
            "local_port": local_port,
            "remote_addr": remote_addr,
            "remote_port": remote_port,
            "state": state,
            "pid": row.dwOwningPid
        })
    
    return connections

def get_udpv6_connections():
    """Get all UDPv6 connections with their owning PIDs"""
    connections = []
    
    # First call to get required buffer size
    buffer_size = wintypes.DWORD()
    result = get_extended_udpv6_table(
        None,
        ctypes.byref(buffer_size),
        True,
        AF_INET6,
        UDP_TABLE_OWNER_PID_ALL,
        0
    )
    
    # Allocate buffer and make second call
    buffer = ctypes.create_string_buffer(buffer_size.value)
    result = get_extended_udpv6_table(
        buffer,
        ctypes.byref(buffer_size),
        True,
        AF_INET6,
        UDP_TABLE_OWNER_PID_ALL,
        0
    )
    
    if result != 0:
        return connections
    
    # Parse the buffer
    num_entries = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD))[0]
    rows = ctypes.cast(
        ctypes.addressof(buffer) + ctypes.sizeof(wintypes.DWORD),
        ctypes.POINTER(MIB_UDP6ROW_OWNER_PID)
    )
    
    for i in range(num_entries):
        row = rows[i]
        local_addr = _inet_ntop(row.LocalAddr)
        local_port = _ntohs(row.dwLocalPort)
        
        connections.append({
            "protocol": "UDPv6",
            "local_addr": local_addr,
            "local_port": local_port,
            "remote_addr": "::",
            "remote_port": 0,
            "state": "LISTENING",
            "pid": row.dwOwningPid
        })
    
    return connections

def get_all_connections():
    """Get all TCP and UDP connections"""
    connections = []
    connections.extend(get_tcp_connections())
    connections.extend(get_udp_connections())
    connections.extend(get_tcpv6_connections())
    connections.extend(get_udpv6_connections())
    return connections

def get_process_path(pid):
    """Get the full path of a process given its PID"""
    try:
        process = psutil.Process(pid)
        return process.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "Unknown"

def get_process_name(pid):
    """Get the name of a process given its PID"""
    try:
        process = psutil.Process(pid)
        return process.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "Unknown"

def get_connection_to_pid_map():
    """Create a mapping from connection tuple to PID"""
    connections = get_all_connections()
    conn_pid_map = {}
    
    for conn in connections:
        # Create a key that uniquely identifies the connection
        if conn["protocol"] in ["TCP", "TCPv6"]:
            key = (
                conn["protocol"],
                conn["local_addr"],
                conn["local_port"],
                conn["remote_addr"],
                conn["remote_port"]
            )
        else:  # UDP, UDPv6
            # For UDP, we use local address and port as key
            key = (
                conn["protocol"],
                conn["local_addr"],
                conn["local_port"]
            )
        
        conn_pid_map[key] = conn["pid"]
    
    return conn_pid_map

def get_pid_to_process_map():
    """Create a mapping from PID to process information"""
    pid_process_map = {}
    
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pid = proc.info['pid']
            pid_process_map[pid] = {
                'name': proc.info['name'],
                'path': proc.info['exe'] or "Unknown"
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    return pid_process_map
