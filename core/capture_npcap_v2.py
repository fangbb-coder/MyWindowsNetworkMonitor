"""
Npcap-based packet capture module for Windows 11 - v2
Optimized for compatibility with different winpcapy versions
"""

import threading
import queue
import time
import socket
import struct
import ctypes
import psutil
import sys
import os
from datetime import datetime

# Try to import winpcapy for Npcap support
try:
    import winpcapy as pcap
    NPCAP_AVAILABLE = True
except ImportError:
    NPCAP_AVAILABLE = False
    print("Warning: winpcapy not available, falling back to raw sockets")

class NpcapCaptureV2:
    def __init__(self, interface='auto', filter_expr='', buffer_size=10000):
        self.interface = interface
        self.filter_expr = filter_expr
        self.buffer_size = buffer_size
        self.packet_queue = queue.Queue(maxsize=buffer_size)
        self.is_running = False
        self.capture_thread = None
        self.pcap_handles = []
        self.use_npcap = NPCAP_AVAILABLE
        self.stats = {
            'packets_captured': 0,
            'packets_dropped': 0,
            'bytes_captured': 0,
            'start_time': None
        }
        
        # Npcap specific settings
        self.snap_len = 65535  # Capture full packets
        self.promiscuous = True  # Enable promiscuous mode
        self.timeout_ms = 1000  # 1 second timeout
    
    def check_admin_privileges(self):
        """Check if running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    
    def check_npcap_installed(self):
        """Check if Npcap is properly installed"""
        if not NPCAP_AVAILABLE:
            return False
        
        try:
            # Try to find all devices using different methods
            devices = self.get_npcap_devices()
            return len(devices) > 0
        except Exception:
            return False
    
    def get_npcap_devices(self):
        """Get all Npcap devices using different methods"""
        devices = []
        
        # Method 1: Try findalldevs
        if hasattr(pcap, 'findalldevs'):
            try:
                devices = pcap.findalldevs()
                return devices
            except Exception as e:
                print(f"findalldevs failed: {e}")
        
        # Method 2: Try findalldev
        if hasattr(pcap, 'findalldev'):
            try:
                devices = pcap.findalldev()
                return devices
            except Exception as e:
                print(f"findalldev failed: {e}")
        
        # Method 3: Try get_all_devs
        if hasattr(pcap, 'get_all_devs'):
            try:
                devices = pcap.get_all_devs()
                return devices
            except Exception as e:
                print(f"get_all_devs failed: {e}")
        
        # Method 4: Try lookupdev
        if hasattr(pcap, 'lookupdev'):
            try:
                device = pcap.lookupdev()
                if device:
                    devices = [device]
                    return devices
            except Exception as e:
                print(f"lookupdev failed: {e}")
        
        # Method 5: Try to get devices using ctypes directly
        try:
            return self.get_devices_direct()
        except Exception as e:
            print(f"Direct device enumeration failed: {e}")
        
        return devices
    
    def get_devices_direct(self):
        """Try to get devices using ctypes directly"""
        try:
            # Try to use pcap_findalldevs directly from the DLL
            if hasattr(pcap, '_pcap'):
                pcap_lib = pcap._pcap
            else:
                # Try to find the pcap DLL
                import ctypes.util
                pcap_lib_path = ctypes.util.find_library('wpcap')
                if pcap_lib_path:
                    pcap_lib = ctypes.CDLL(pcap_lib_path)
                else:
                    print("Cannot find wpcap.dll")
                    return []
            
            # Define the necessary structures and functions
            class pcap_if_t(ctypes.Structure):
                pass
            
            # Setup the structure fields
            pcap_if_t._fields_ = [
                ('next', ctypes.POINTER(pcap_if_t)),
                ('name', ctypes.c_char_p),
                ('description', ctypes.c_char_p),
                ('addresses', ctypes.c_void_p),
                ('flags', ctypes.c_uint)
            ]
            
            # Define the function
            pcap_findalldevs = pcap_lib.pcap_findalldevs
            pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(pcap_if_t)), ctypes.c_char_p]
            pcap_findalldevs.restype = ctypes.c_int
            
            # Call the function
            alldevs = ctypes.POINTER(pcap_if_t)()
            errbuf = ctypes.create_string_buffer(256)
            
            result = pcap_findalldevs(ctypes.byref(alldevs), errbuf)
            
            if result != 0:
                print(f"pcap_findalldevs failed: {errbuf.value.decode('utf-8')}")
                return []
            
            # Extract the device names
            devices = []
            dev = alldevs
            while dev:
                name = dev.contents.name.decode('utf-8') if dev.contents.name else ""
                desc = dev.contents.description.decode('utf-8') if dev.contents.description else ""
                devices.append(f"{name} ({desc})" if desc else name)
                dev = dev.contents.next
            
            return devices
            
        except Exception as e:
            print(f"Direct device enumeration error: {e}")
            return []
    
    def get_interfaces(self):
        """Get all available network interfaces with Npcap"""
        interfaces = []
        
        if not NPCAP_AVAILABLE:
            print("Npcap not available, using fallback method")
            return self._get_interfaces_fallback()
        
        try:
            # Use multiple methods to get devices
            devices = self.get_npcap_devices()
            print(f"Npcap found {len(devices)} devices")
            
            if not devices:
                print("No Npcap devices found, using fallback")
                return self._get_interfaces_fallback()
            
            # Get network interfaces via psutil for IP information
            try:
                psutil_interfaces = psutil.net_if_addrs()
                psutil_stats = psutil.net_if_stats()
                
                for device in devices:
                    # Try to parse device name and description
                    if '(' in device and ')' in device:
                        device_name = device.split(' (')[0]
                        description = device.split(' (')[1][:-1]
                    else:
                        device_name = device
                        description = device
                    
                    # Try to match with psutil interfaces
                    matched_ips = []
                    is_up = True
                    final_name = device_name
                    
                    for psutil_name, addr_list in psutil_interfaces.items():
                        # Check if device name contains psutil name or vice versa
                        if (device_name.lower() in psutil_name.lower() or 
                            psutil_name.lower() in device_name.lower() or
                            self._normalize_name(device_name) == self._normalize_name(psutil_name)):
                            
                            # Check if interface is up
                            if psutil_name in psutil_stats:
                                is_up = psutil_stats[psutil_name].isup
                            
                            # Get IP addresses
                            for addr in addr_list:
                                if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                                    matched_ips.append({
                                        'ip': addr.address,
                                        'netmask': addr.netmask
                                    })
                            
                            # Use the more descriptive name
                            final_name = psutil_name
                            break
                    
                    # Add interface
                    interfaces.append({
                        'name': final_name,
                        'description': description,
                        'ip': matched_ips[0]['ip'] if matched_ips else 'N/A',
                        'netmask': matched_ips[0]['netmask'] if matched_ips else '',
                        'is_up': is_up,
                        'npcap_device': device_name  # Store the actual device name for pcap
                    })
                
                print(f"Successfully mapped {len(interfaces)} interfaces")
                return interfaces
                
            except Exception as e:
                print(f"Error using psutil: {e}")
                
                # Fallback - just return device names
                for device in devices:
                    if '(' in device and ')' in device:
                        device_name = device.split(' (')[0]
                        description = device.split(' (')[1][:-1]
                    else:
                        device_name = device
                        description = device
                    
                    interfaces.append({
                        'name': device_name,
                        'description': description,
                        'ip': 'N/A',
                        'netmask': '',
                        'is_up': True,
                        'npcap_device': device_name
                    })
                
                return interfaces
                
        except Exception as e:
            print(f"Error getting Npcap devices: {e}")
            return self._get_interfaces_fallback()
    
    def _normalize_name(self, name):
        """Normalize interface names for comparison"""
        # Convert to lowercase and remove common variations
        return name.lower().replace('-', '_').replace(' ', '_')
    
    def _get_interfaces_fallback(self):
        """Fallback method to get interfaces without Npcap"""
        interfaces = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            for name, addr_list in addrs.items():
                # Check if interface is up
                if name in stats and not stats[name].isup:
                    continue
                    
                for addr in addr_list:
                    if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                        interfaces.append({
                            'name': name,
                            'description': name,
                            'ip': addr.address,
                            'netmask': addr.netmask,
                            'is_up': stats[name].isup if name in stats else True,
                            'npcap_device': name  # Use the name as device
                        })
                        break  # Only add one IP per interface
        except Exception as e:
            print(f"Fallback interface detection failed: {e}")
        
        return interfaces
    
    def start_capture(self, interface_ip=None):
        """Start packet capture using Npcap"""
        if self.is_running:
            print("Capture is already running")
            return True
        
        # Update interface if provided
        if interface_ip:
            self.interface = interface_ip
        
        if not self.use_npcap or not NPCAP_AVAILABLE:
            print("Npcap not available, falling back to raw sockets")
            return self._start_raw_socket_capture()
        
        return self._start_npcap_capture()
    
    def _start_npcap_capture(self):
        """Start capture using Npcap with proper API"""
        print("Starting Npcap capture...")
        
        try:
            # Check if running with admin privileges
            if not self.check_admin_privileges():
                print("Warning: Not running as administrator, capture may fail")
            
            # Get all interfaces
            interfaces = self.get_interfaces()
            if not interfaces:
                print("No interfaces found")
                return False
            
            # Find interfaces to capture on
            devices_to_capture = []
            
            if self.interface == 'auto':
                # Auto-select first few interfaces that are up
                up_interfaces = [i for i in interfaces if i.get('is_up', True)]
                devices_to_capture = [i['npcap_device'] for i in up_interfaces[:3]]
            else:
                # Try to match interface by IP or name
                for iface in interfaces:
                    if (iface['ip'] == self.interface or 
                        self.interface in iface['name'] or 
                        iface['name'] in self.interface or
                        self.interface in iface['npcap_device']):
                        devices_to_capture = [iface['npcap_device']]
                        break
                
                # If no match, try to use the interface name directly
                if not devices_to_capture:
                    devices_to_capture = [self.interface]
            
            if not devices_to_capture:
                print("No matching interface found")
                return False
            
            print(f"Attempting to open devices: {devices_to_capture}")
            
            # Open handles for each device
            self.pcap_handles = []
            
            for device_name in devices_to_capture:
                try:
                    print(f"Opening device: {device_name}")
                    
                    # Try to open the device with Npcap
                    handle = pcap.open_live(
                        device_name, 
                        self.snap_len, 
                        1 if self.promiscuous else 0,  # promiscuous mode
                        self.timeout_ms
                    )
                    
                    if not handle:
                        print(f"Failed to open device {device_name}: handle is None")
                        continue
                    
                    # Set BPF filter if provided
                    if self.filter_expr:
                        print(f"Setting filter: {self.filter_expr}")
                        try:
                            handle.setfilter(self.filter_expr)
                        except Exception as e:
                            print(f"Failed to set filter: {e}")
                            # Continue without filter
                            pass
                    
                    self.pcap_handles.append((handle, device_name))
                    print(f"Successfully opened device: {device_name}")
                    
                except Exception as e:
                    print(f"Failed to open device {device_name}: {e}")
                    continue
            
            if not self.pcap_handles:
                print("Failed to open any Npcap devices")
                # Fall back to raw sockets
                return self._start_raw_socket_capture()
            
            # Start capture thread
            self.is_running = True
            self.stats['start_time'] = datetime.now()
            
            self.capture_thread = threading.Thread(target=self._npcap_capture_loop)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
            print(f"Successfully started Npcap capture on {len(self.pcap_handles)} devices")
            return True
            
        except Exception as e:
            print(f"Error starting Npcap capture: {e}")
            # Fall back to raw sockets
            return self._start_raw_socket_capture()
    
    def _npcap_capture_loop(self):
        """Main capture loop for Npcap"""
        while self.is_running:
            try:
                for handle, device_name in self.pcap_handles:
                    try:
                        # Try to get a packet
                        packet_data = handle.next()
                        
                        if packet_data:
                            self.stats['packets_captured'] += 1
                            self.stats['bytes_captured'] += len(packet_data)
                            
                            # Process the packet
                            packet_info = self._process_packet(packet_data)
                            
                            if packet_info:
                                # Add to queue if not full
                                if not self.packet_queue.full():
                                    self.packet_queue.put(packet_info)
                                else:
                                    self.stats['packets_dropped'] += 1
                    
                    except Exception as e:
                        if self.is_running:  # Only print if still running
                            print(f"Error capturing from {device_name}: {e}")
                        continue
                
                # Small delay to prevent busy loop
                time.sleep(0.001)
                
            except Exception as e:
                if self.is_running:
                    print(f"Error in Npcap capture loop: {e}")
                time.sleep(0.01)
    
    def _start_raw_socket_capture(self):
        """Fallback: Start capture using raw sockets"""
        print("Starting capture using raw sockets...")
        
        # This is just a placeholder - we should implement a proper fallback
        # For now, we'll just print an error message
        print("Raw socket capture not implemented")
        print("Please install Npcap to enable packet capture")
        return False
    
    def stop_capture(self):
        """Stop packet capture"""
        if not self.is_running:
            return
        
        print("Stopping capture...")
        self.is_running = False
        
        # Wait for thread to finish
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
            self.capture_thread = None
        
        # Close handles
        for handle, device_name in self.pcap_handles:
            try:
                if hasattr(handle, 'close'):
                    handle.close()
                else:
                    # Some winpcapy versions might use different method
                    pcap.close(handle)
            except Exception as e:
                print(f"Error closing device {device_name}: {e}")
        
        self.pcap_handles = []
        
        print(f"Capture stopped. Stats: {self.stats}")
    
    def _process_packet(self, packet_data):
        """Process a captured packet and extract relevant information"""
        try:
            # Ensure we have enough data for an IP header
            if len(packet_data) < 20:
                return None
            
            # Parse IP header (first 20 bytes for IPv4)
            ip_header = packet_data[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            
            # Skip if not IPv4
            if version != 4:
                return None
                
            iph_length = ihl * 4
            ttl = iph[5]
            protocol = iph[6]
            src_addr = socket.inet_ntoa(iph[8])
            dst_addr = socket.inet_ntoa(iph[9])
            
            # Basic packet info
            packet_info = {
                'version': version,
                'ihl': ihl,
                'ttl': ttl,
                'protocol': protocol,
                'src_ip': src_addr,
                'dst_ip': dst_addr,
                'length': len(packet_data)
            }
            
            # Parse transport layer
            if protocol == 6 and len(packet_data) >= iph_length + 20:  # TCP
                tcp_header = packet_data[iph_length:iph_length+20]
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                
                packet_info.update({
                    'transport_protocol': 'TCP',
                    'src_port': tcph[0],
                    'dst_port': tcph[1]
                })
                
            elif protocol == 17 and len(packet_data) >= iph_length + 8:  # UDP
                udp_header = packet_data[iph_length:iph_length+8]
                udph = struct.unpack('!HHHH', udp_header)
                
                packet_info.update({
                    'transport_protocol': 'UDP',
                    'src_port': udph[0],
                    'dst_port': udph[1]
                })
                
            elif protocol == 1:  # ICMP
                packet_info.update({
                    'transport_protocol': 'ICMP'
                })
            
            return packet_info
            
        except Exception as e:
            # Silently ignore packet processing errors
            return None
    
    def get_packet(self, block=True, timeout=None):
        """Get a packet from the queue"""
        try:
            return self.packet_queue.get(block=block, timeout=timeout)
        except queue.Empty:
            return None
    
    def get_queue_size(self):
        """Get the current size of the packet queue"""
        return self.packet_queue.qsize()
    
    def get_stats(self):
        """Get the current capture statistics"""
        return self.stats.copy()


# Create an alias for compatibility with existing code
Capture = NpcapCaptureV2