import threading
import queue
import time
import socket
import struct
import select
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

class Capture:
    def __init__(self, interface='auto', filter_expr='', buffer_size=10000):
        self.interface = interface
        self.filter_expr = filter_expr
        self.buffer_size = buffer_size
        self.packet_queue = queue.Queue(maxsize=buffer_size)
        self.is_running = False
        self.capture_thread = None
        self.sockets = []
        self.pcap_handles = []  # For Npcap handles
        self.use_npcap = NPCAP_AVAILABLE
        self.stats = {
            'packets_captured': 0,
            'packets_dropped': 0,
            'bytes_captured': 0,
            'start_time': None
        }
    
    def check_permissions(self):
        """Check if we have administrator privileges (required for raw sockets)"""
        print("Performing comprehensive permission check...")
        
        # If we can use Npcap, permissions are less critical
        if self.use_npcap:
            print("Npcap available, permissions check relaxed")
            return True
            
        # Method 1: Direct admin check
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            print(f"IsUserAnAdmin check: {is_admin}")
            if is_admin:
                print("Direct admin check passed")
                return True
        except Exception as e:
            print(f"IsUserAnAdmin check failed: {e}")
        
        # Method 2: Token elevation check
        try:
            import ctypes.wintypes
            
            TOKEN_QUERY = 0x0008
            TokenElevation = 20
            
            class TOKEN_ELEVATION(ctypes.Structure):
                _fields_ = [("TokenIsElevated", ctypes.wintypes.DWORD)]
            
            token = ctypes.wintypes.HANDLE()
            process = ctypes.windll.kernel32.GetCurrentProcess()
            
            if ctypes.windll.advapi32.OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(token)):
                elevation = TOKEN_ELEVATION()
                size = ctypes.wintypes.DWORD()
                size.value = ctypes.sizeof(elevation)
                
                if ctypes.windll.advapi32.GetTokenInformation(token, TokenElevation, ctypes.byref(elevation), size, ctypes.byref(size)):
                    token_elevated = bool(elevation.TokenIsElevated)
                    print(f"Token elevation check: {token_elevated}")
                    ctypes.windll.kernel32.CloseHandle(token)
                    if token_elevated:
                        print("Token elevation check passed")
                        return True
                
                ctypes.windll.kernel32.CloseHandle(token)
        except Exception as e:
            print(f"Token elevation check failed: {e}")
        
        # Method 3: Net session check (alternative admin verification)
        try:
            import subprocess
            result = subprocess.run(['net', 'session'], capture_output=True, text=True)
            net_session_ok = result.returncode == 0
            print(f"Net session check: {net_session_ok}")
            if net_session_ok:
                print("Net session check passed")
                return True
        except Exception as e:
            print(f"Net session check failed: {e}")
        
        # Method 4: File access test
        try:
            system_dir = os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'system32')
            test_file = os.path.join(system_dir, 'config', 'system')
            
            with open(test_file, 'rb') as f:
                f.read(1)
            print("File access test passed")
            return True
        except Exception as e:
            print(f"File access test failed: {e}")
        
        print("All permission checks failed")
        return False

    def check_npcap_installed(self):
        """
        Check if Npcap is installed and available.
        This is now the preferred method over raw sockets.
        """
        print("Checking if Npcap is available...")
        if NPCAP_AVAILABLE:
            print("Npcap/winpcapy is available")
            # Test if we can access devices
            try:
                devices = pcap.findalldevs()
                print(f"Found {len(devices)} network devices")
                return True
            except Exception as e:
                print(f"Error accessing Npcap devices: {e}")
                return False
        else:
            print("Npcap/winpcapy not available")
            return False
    
    def get_interfaces(self):
        """Get a list of available network interfaces with details"""
        interfaces = []
        try:
            # First try using psutil
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            for name, addr_list in addrs.items():
                # Check if interface is up
                if name in stats and not stats[name].isup:
                    continue
                    
                for addr in addr_list:
                    if addr.family == socket.AF_INET:
                        # It's an IPv4 address
                        if addr.address == '127.0.0.1':
                            continue
                            
                        interfaces.append({
                            'name': name,
                            'ip': addr.address,
                            'netmask': addr.netmask
                        })
                            
            # If we have valid interfaces, return them
            if interfaces:
                print(f"Found {len(interfaces)} interfaces via psutil")
                return interfaces
                
        except Exception as e:
            print(f"Error getting interfaces with psutil: {e}")
        
        # If psutil didn't work, try to get available network interfaces directly
        try:
            # Get local IP addresses
            hostname = socket.gethostname()
            local_ips = socket.gethostbyname_ex(hostname)[2]
            
            # Add any additional IP addresses that might be on network interfaces
            for ip in local_ips:
                if ip != '127.0.0.1' and not any(iface['ip'] == ip for iface in interfaces):
                    interfaces.append({
                        'name': 'Interface',
                        'ip': ip,
                        'netmask': '255.255.255.0'
                    })
                    
            print(f"Found {len(interfaces)} interfaces via socket")
            
        except Exception as e:
            print(f"Error getting interfaces with socket: {e}")
            
        # Last resort - check for common network interface IP ranges
        if not interfaces:
            print("No interfaces found, trying to detect network adapters")
            try:
                # Create a temporary socket to detect local IPs
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                
                if local_ip and local_ip != '127.0.0.1':
                    interfaces.append({
                        'name': 'Detected Interface',
                        'ip': local_ip,
                        'netmask': '255.255.255.0'
                    })
                    print(f"Detected local IP: {local_ip}")
            except Exception as e:
                print(f"Error detecting local IP: {e}")
                
        return interfaces
    
    def start_capture(self, interface_ip=None):
        """Start the packet capture"""
        if self.is_running:
            print("Capture is already running")
            return True
        
        # Update interface if provided
        if interface_ip:
            self.interface = interface_ip
            
        if self.use_npcap and NPCAP_AVAILABLE:
            return self._start_npcap_capture()
        else:
            return self._start_raw_socket_capture()
    
    def _start_npcap_capture(self):
        """Start capture using Npcap"""
        print("Starting capture using Npcap...")
        
        try:
            # First try to get all Npcap devices
            devices = pcap.findalldevs()
            if not devices:
                print("No network devices found via Npcap")
                # Fall back to raw sockets
                return self._start_raw_socket_capture()
            
            print(f"Found Npcap devices: {devices}")
            
            # Setup handles for selected interfaces
            self.pcap_handles = []
            interfaces_to_capture = []
            
            available_interfaces = self.get_interfaces()
            available_ips = [iface['ip'] for iface in available_interfaces]
            
            if self.interface == 'auto':
                # Try to find devices with associated IPs first
                matched_devices = []
                for device in devices:
                    for iface in available_interfaces:
                        if device in iface['name'] or iface['name'] in device:
                            matched_devices.append(device)
                            break
                
                # If no matched devices, use first few devices
                if matched_devices:
                    interfaces_to_capture = matched_devices[:3]
                else:
                    interfaces_to_capture = devices[:3]  # Capture on first 3 devices
            else:
                # Try to match interface by IP or name
                if self.interface in available_ips:
                    # Find device name for this IP
                    for iface in available_interfaces:
                        if iface['ip'] == self.interface:
                            for device in devices:
                                if device in iface['name'] or iface['name'] in device:
                                    interfaces_to_capture = [device]
                                    break
                            if not interfaces_to_capture:
                                interfaces_to_capture = [devices[0]]  # Fallback
                            break
                else:
                    # Try to match by name
                    for device in devices:
                        if self.interface in device or device in self.interface:
                            interfaces_to_capture = [device]
                            break
                    if not interfaces_to_capture:
                        interfaces_to_capture = [devices[0]]  # Fallback to first device
            
            print(f"Attempting to capture on devices: {interfaces_to_capture}")
            
            for device_name in interfaces_to_capture:
                try:
                    # Create pcap handle
                    handle = pcap.open_live(device_name, 65536, 1, 1000)  # promiscuous mode
                    if self.filter_expr:
                        handle.setfilter(self.filter_expr)
                    self.pcap_handles.append((handle, device_name))
                    print(f"Successfully opened device: {device_name}")
                except Exception as e:
                    print(f"Failed to open device {device_name}: {e}")
            
            if not self.pcap_handles:
                print("Failed to open any devices with Npcap, falling back to raw sockets")
                return self._start_raw_socket_capture()
                
            self.is_running = True
            self.stats['start_time'] = datetime.now()
            
            # Start capture thread
            self.capture_thread = threading.Thread(target=self._npcap_capture_loop)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
            print(f"Started Npcap capture on {len(self.pcap_handles)} devices")
            return True
            
        except Exception as e:
            print(f"Error starting Npcap capture: {e}")
            print("Falling back to raw sockets")
            return self._start_raw_socket_capture()
    
    def _start_raw_socket_capture(self):
        """Start capture using raw sockets (fallback method)"""
        print("Starting capture using raw sockets...")
        
        if not self.check_permissions():
            print("Error: Administrator privileges required for raw sockets")
            return False
            
        # Setup sockets
        self.sockets = []
        ips_to_bind = []
        
        available_interfaces = self.get_interfaces()
        available_ips = [iface['ip'] for iface in available_interfaces]
        
        if self.interface == 'auto':
            ips_to_bind = available_ips
        elif self.interface in available_ips:
            ips_to_bind = [self.interface]
        else:
            # Check if it matches a name
            found = False
            for iface in available_interfaces:
                if iface['name'] == self.interface:
                    ips_to_bind = [iface['ip']]
                    found = True
                    break
            
            if not found:
                ips_to_bind = [self.interface]
            
        if not ips_to_bind:
            print("No interfaces found to bind")
            return False
            
        print(f"Attempting to bind to IPs: {ips_to_bind}")
        
        for ip in ips_to_bind:
            try:
                # Create raw socket
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                s.bind((ip, 0))
                
                # Include IP headers
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                
                # Enable promiscuous mode (RCVALL_ON)
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                
                self.sockets.append(s)
                print(f"Successfully bound to {ip}")
            except Exception as e:
                print(f"Failed to bind to {ip}: {e}")
                
        if not self.sockets:
            print("Failed to create any sockets. Ensure you are running as Administrator.")
            return False
            
        self.is_running = True
        self.stats['start_time'] = datetime.now()
        
        # Start capture thread
        self.capture_thread = threading.Thread(target=self._raw_socket_capture_loop)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        print(f"Started raw socket capture on {len(self.sockets)} interfaces")
        return True
    
    def stop_capture(self):
        """Stop the packet capture"""
        if not self.is_running:
            return
        
        self.is_running = False
        
        # Wait for the thread to finish
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
        
        # Close handles/sockets
        if self.use_npcap and self.pcap_handles:
            for handle, device_name in self.pcap_handles:
                try:
                    handle.close()
                except:
                    pass
            self.pcap_handles = []
        elif self.sockets:
            for s in self.sockets:
                try:
                    # Disable promiscuous mode
                    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    s.close()
                except:
                    pass
            self.sockets = []
        
        print(f"Stopped capture. Stats: {self.stats}")
    
    def _npcap_capture_loop(self):
        """Capture loop using Npcap"""
        while self.is_running:
            try:
                for handle, device_name in self.pcap_handles:
                    try:
                        # Non-blocking read
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
                        if self.is_running:  # Only print if we're still running
                            print(f"Error capturing packet from {device_name}: {e}")
                        continue
            except Exception as e:
                if self.is_running:
                    print(f"Error in Npcap capture loop: {e}")
                time.sleep(0.001)  # Small delay to prevent busy loop
    
    def _raw_socket_capture_loop(self):
        """Main capture loop using select with raw sockets"""
        while self.is_running:
            try:
                if not self.sockets:
                    break
                    
                # Use select to wait for data on any of the sockets
                # timeout=1.0 allows the loop to check is_running periodically
                readable, _, _ = select.select(self.sockets, [], [], 1.0)
                
                for s in readable:
                    try:
                        # Receive packet
                        # 65535 is the max IP packet size
                        packet, addr = s.recvfrom(65535)
                        
                        self.stats['packets_captured'] += 1
                        self.stats['bytes_captured'] += len(packet)
                        
                        # Process the packet
                        packet_info = self._process_packet(packet)
                        
                        if packet_info:
                            # Add to queue if not full
                            if not self.packet_queue.full():
                                self.packet_queue.put(packet_info)
                            else:
                                self.stats['packets_dropped'] += 1
                    except OSError:
                        # Socket might be closed
                        continue
                    except Exception as e:
                        # print(f"Error receiving packet: {e}")
                        continue
            except Exception as e:
                if self.is_running:
                    print(f"Error in raw socket capture loop: {e}")
                time.sleep(0.001)  # Small delay to prevent busy loop
    
    def _process_packet(self, packet_data):
        """Process a captured packet and extract relevant information"""
        try:
            # Ensure we have enough data
            if len(packet_data) < 20:
                return None
            
            # Parse IP header (first 20 bytes)
            ip_header = packet_data[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            
            ttl = iph[5]
            protocol = iph[6]
            src_addr = socket.inet_ntoa(iph[8])
            dst_addr = socket.inet_ntoa(iph[9])
            
            packet_info = {
                'version': version,
                'ihl': ihl,
                'ttl': ttl,
                'protocol': protocol,
                'src_ip': src_addr,
                'dst_ip': dst_addr,
                'length': len(packet_data)
            }
            
            # Parse transport layer based on protocol
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
                
            elif protocol == 1: # ICMP
                packet_info.update({
                    'transport_protocol': 'ICMP'
                })
                
            return packet_info
            
        except Exception as e:
            # print(f"Error processing packet: {e}")
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

if __name__ == "__main__":
    # Test the capture
    capture = Capture()
    
    if capture.use_npcap:
        print("Using Npcap for packet capture")
    else:
        if not capture.check_permissions():
            print("Administrator privileges are required to run this script with raw sockets.")
            print("Please run the terminal as Administrator.")
            exit(1)
        
    print("Available interfaces (IPs):")
    for iface in capture.get_interfaces():
        print(f"  - {iface}")
        
    if capture.start_capture():
        print("Capturing for 5 seconds...")
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            pass
        finally:
            capture.stop_capture()
            
    print("Done.")