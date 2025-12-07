"""
适配特定winpcapy版本的捕获模块
针对使用类结构而非函数的winpcapy实现
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
    # 检查可用的类
    HAS_WINPCAP_CLASSES = all(hasattr(pcap, cls) for cls in ['WinPcap', 'WinPcapDevices'])
    if not HAS_WINPCAP_CLASSES:
        print("Warning: winpcapy module does not have expected class structure")
        NPCAP_AVAILABLE = False
    else:
        NPCAP_AVAILABLE = True
except ImportError:
    NPCAP_AVAILABLE = False
    print("Warning: winpcapy not available, falling back to raw sockets")

class WinPcapClassCapture:
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
        
        # Initialize winpcapy objects
        if self.use_npcap:
            try:
                self.device_finder = pcap.WinPcapDevices()
                self.pcap_utils = pcap.WinPcapUtils()
            except Exception as e:
                print(f"Error initializing winpcapy objects: {e}")
                self.use_npcap = False
    
    def check_admin_privileges(self):
        """Check if running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    
    def check_npcap_installed(self):
        """Check if Npcap is properly installed"""
        if not NPCAP_AVAILABLE or not self.use_npcap:
            return False
        
        try:
            # Try to get devices
            devices = self.get_npcap_devices()
            return len(devices) > 0
        except Exception:
            return False
    
    def get_npcap_devices(self):
        """Get all Npcap devices using class-based API"""
        devices = []
        
        if not self.use_npcap:
            return devices
        
        try:
            # 尝试使用WinPcapDevices类
            if hasattr(self, 'device_finder'):
                try:
                    device_list = self.device_finder.get_all_devices()
                    if device_list:
                        for device in device_list:
                            # 获取设备名称和描述
                            name = getattr(device, 'name', str(device))
                            desc = getattr(device, 'description', name)
                            devices.append(f"{name} ({desc})" if desc != name else name)
                        return devices
                except Exception as e:
                    print(f"WinPcapDevices.get_all_devices failed: {e}")
                
                # 尝试其他可能的方法
                try:
                    if hasattr(self.device_finder, 'find_all_devs'):
                        device_list = self.device_finder.find_all_devs()
                        for device in device_list:
                            name = getattr(device, 'name', str(device))
                            desc = getattr(device, 'description', name)
                            devices.append(f"{name} ({desc})" if desc != name else name)
                        return devices
                except Exception as e:
                    print(f"WinPcapDevices.find_all_devs failed: {e}")
            
            # 尝试使用WinPcap类
            if hasattr(pcap, 'WinPcap'):
                try:
                    winpcap_obj = pcap.WinPcap()
                    if hasattr(winpcap_obj, 'findalldevs'):
                        devices = winpcap_obj.findalldevs()
                        return devices
                    elif hasattr(winpcap_obj, 'get_all_devices'):
                        devices = winpcap_obj.get_all_devices()
                        return devices
                except Exception as e:
                    print(f"WinPcap class method failed: {e}")
            
            # 尝试使用WinPcapUtils类
            if hasattr(self, 'pcap_utils'):
                try:
                    if hasattr(self.pcap_utils, 'get_all_devs'):
                        devices = self.pcap_utils.get_all_devs()
                        return devices
                    elif hasattr(self.pcap_utils, 'findalldevs'):
                        devices = self.pcap_utils.findalldevs()
                        return devices
                except Exception as e:
                    print(f"WinPcapUtils method failed: {e}")
            
            # 最后尝试直接调用DLL
            return self.get_devices_direct()
            
        except Exception as e:
            print(f"Error getting devices: {e}")
            return []
    
    def get_devices_direct(self):
        """Try to get devices using ctypes directly"""
        try:
            # 尝试找到wpcap.dll
            import ctypes.util
            pcap_lib_path = ctypes.util.find_library('wpcap')
            if pcap_lib_path:
                pcap_lib = ctypes.CDLL(pcap_lib_path)
            else:
                raise Exception("找不到wpcap.dll")
            
            # 定义必要的结构和函数
            class pcap_if_t(ctypes.Structure):
                pass
            
            # 设置结构字段
            pcap_if_t._fields_ = [
                ('next', ctypes.POINTER(pcap_if_t)),
                ('name', ctypes.c_char_p),
                ('description', ctypes.c_char_p),
                ('addresses', ctypes.c_void_p),
                ('flags', ctypes.c_uint)
            ]
            
            # 定义函数
            pcap_findalldevs = pcap_lib.pcap_findalldevs
            pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(pcap_if_t)), ctypes.c_char_p]
            pcap_findalldevs.restype = ctypes.c_int
            
            # 调用函数
            alldevs = ctypes.POINTER(pcap_if_t)()
            errbuf = ctypes.create_string_buffer(256)
            
            result = pcap_findalldevs(ctypes.byref(alldevs), errbuf)
            
            if result != 0:
                raise Exception(f"pcap_findalldevs失败: {errbuf.value.decode('utf-8')}")
            
            # 提取设备名称
            devices = []
            dev = alldevs
            while dev:
                name = dev.contents.name.decode('utf-8') if dev.contents.name else ""
                desc = dev.contents.description.decode('utf-8') if dev.contents.description else ""
                devices.append(f"{name} ({desc})" if desc else name)
                dev = dev.contents.next
            
            return devices
            
        except Exception as e:
            raise Exception(f"直接设备枚举错误: {e}")
    
    def get_interfaces(self):
        """Get all available network interfaces with Npcap"""
        interfaces = []
        
        if not self.use_npcap:
            print("Npcap not available, using fallback method")
            return self._get_interfaces_fallback()
        
        try:
            # 获取Npcap设备
            devices = self.get_npcap_devices()
            print(f"Npcap找到 {len(devices)} 个设备")
            
            if not devices:
                print("No Npcap devices found, using fallback")
                return self._get_interfaces_fallback()
            
            # 获取网络接口信息
            try:
                psutil_interfaces = psutil.net_if_addrs()
                psutil_stats = psutil.net_if_stats()
                
                for device in devices:
                    # 解析设备名称和描述
                    if '(' in device and ')' in device:
                        device_name = device.split(' (')[0]
                        description = device.split(' (')[1][:-1]
                    else:
                        device_name = device
                        description = device
                    
                    # 尝试匹配psutil接口
                    matched_ips = []
                    is_up = True
                    final_name = device_name
                    
                    for psutil_name, addr_list in psutil_interfaces.items():
                        # 检查名称是否匹配
                        if (device_name.lower() in psutil_name.lower() or 
                            psutil_name.lower() in device_name.lower() or
                            description.lower() in psutil_name.lower() or
                            psutil_name.lower() in description.lower()):
                            
                            # 检查接口是否活动
                            if psutil_name in psutil_stats:
                                is_up = psutil_stats[psutil_name].isup
                            
                            # 获取IP地址
                            for addr in addr_list:
                                if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                                    matched_ips.append({
                                        'ip': addr.address,
                                        'netmask': addr.netmask
                                    })
                            
                            # 使用更具描述性的名称
                            final_name = psutil_name
                            break
                    
                    # 添加接口
                    interfaces.append({
                        'name': final_name,
                        'description': description,
                        'ip': matched_ips[0]['ip'] if matched_ips else 'N/A',
                        'netmask': matched_ips[0]['netmask'] if matched_ips else '',
                        'is_up': is_up,
                        'npcap_device': device_name  # 存储实际的设备名称
                    })
                
                print(f"成功映射 {len(interfaces)} 个接口")
                return interfaces
                
            except Exception as e:
                print(f"使用psutil出错: {e}")
                
                # 回退 - 只返回设备名称
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
            print(f"获取Npcap设备出错: {e}")
            return self._get_interfaces_fallback()
    
    def _get_interfaces_fallback(self):
        """Fallback method to get interfaces without Npcap"""
        interfaces = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            for name, addr_list in addrs.items():
                # 检查接口是否活动
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
                            'npcap_device': name  # 使用名称作为设备
                        })
                        break  # 每个接口只添加一个IP
        except Exception as e:
            print(f"回退接口检测失败: {e}")
        
        return interfaces
    
    def start_capture(self, interface_ip=None):
        """Start packet capture using Npcap"""
        if self.is_running:
            print("Capture is already running")
            return True
        
        # 更新接口
        if interface_ip:
            self.interface = interface_ip
        
        if not self.use_npcap:
            print("Npcap not available, falling back to raw sockets")
            return self._start_raw_socket_capture()
        
        return self._start_npcap_capture()
    
    def _start_npcap_capture(self):
        """Start capture using Npcap with class-based API"""
        print("Starting Npcap capture...")
        
        try:
            # 检查管理员权限
            if not self.check_admin_privileges():
                print("Warning: Not running as administrator, capture may fail")
            
            # 获取所有接口
            interfaces = self.get_interfaces()
            if not interfaces:
                print("No interfaces found")
                return False
            
            # 找到要捕获的接口
            devices_to_capture = []
            
            if self.interface == 'auto':
                # 自动选择前几个活动的接口
                up_interfaces = [i for i in interfaces if i.get('is_up', True)]
                devices_to_capture = [i['npcap_device'] for i in up_interfaces[:3]]
            else:
                # 尝试匹配IP或名称
                for iface in interfaces:
                    if (iface['ip'] == self.interface or 
                        self.interface in iface['name'] or 
                        iface['name'] in self.interface or
                        self.interface in iface['npcap_device']):
                        devices_to_capture = [iface['npcap_device']]
                        break
                
                # 如果没有匹配，直接使用接口名称
                if not devices_to_capture:
                    devices_to_capture = [self.interface]
            
            if not devices_to_capture:
                print("No matching interface found")
                return False
            
            print(f"尝试打开设备: {devices_to_capture}")
            
            # 为每个设备打开句柄
            self.pcap_handles = []
            
            for device_name in devices_to_capture:
                try:
                    print(f"打开设备: {device_name}")
                    
                    # 尝试使用类API打开设备
                    handle = self._open_device(device_name)
                    
                    if not handle:
                        print(f"无法打开设备 {device_name}: 句柄为空")
                        continue
                    
                    # 设置BPF过滤器
                    if self.filter_expr:
                        print(f"设置过滤器: {self.filter_expr}")
                        try:
                            self._set_filter(handle, self.filter_expr)
                        except Exception as e:
                            print(f"设置过滤器失败: {e}")
                            # 继续但不使用过滤器
                    
                    self.pcap_handles.append((handle, device_name))
                    print(f"成功打开设备: {device_name}")
                    
                except Exception as e:
                    print(f"打开设备 {device_name} 失败: {e}")
                    continue
            
            if not self.pcap_handles:
                print("无法打开任何Npcap设备")
                # 回退到原始套接字
                return self._start_raw_socket_capture()
            
            # 启动捕获线程
            self.is_running = True
            self.stats['start_time'] = datetime.now()
            
            self.capture_thread = threading.Thread(target=self._npcap_capture_loop)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
            print(f"成功在 {len(self.pcap_handles)} 个设备上启动Npcap捕获")
            return True
            
        except Exception as e:
            print(f"启动Npcap捕获出错: {e}")
            # 回退到原始套接字
            return self._start_raw_socket_capture()
    
    def _open_device(self, device_name):
        """使用类API打开设备"""
        # 尝试多种方法打开设备
        methods = [
            # 尝试使用WinPcap类
            lambda: self._try_winpcap_open(device_name),
            # 尝试使用WinPcapUtils
            lambda: self._try_winpcaputils_open(device_name),
            # 尝试直接调用DLL
            lambda: self._try_direct_open(device_name)
        ]
        
        for method in methods:
            try:
                handle = method()
                if handle:
                    return handle
            except Exception as e:
                print(f"打开方法失败: {e}")
                continue
        
        return None
    
    def _try_winpcap_open(self, device_name):
        """使用WinPcap类打开设备"""
        if hasattr(pcap, 'WinPcap'):
            winpcap_obj = pcap.WinPcap()
            if hasattr(winpcap_obj, 'open_live'):
                return winpcap_obj.open_live(
                    device_name,
                    self.snap_len,
                    1 if self.promiscuous else 0,
                    self.timeout_ms
                )
        return None
    
    def _try_winpcaputils_open(self, device_name):
        """使用WinPcapUtils打开设备"""
        if hasattr(self, 'pcap_utils') and hasattr(self.pcap_utils, 'open_live'):
            return self.pcap_utils.open_live(
                device_name,
                self.snap_len,
                1 if self.promiscuous else 0,
                self.timeout_ms
            )
        return None
    
    def _try_direct_open(self, device_name):
        """尝试直接调用DLL打开设备"""
        try:
            # 尝试找到wpcap.dll
            import ctypes.util
            pcap_lib_path = ctypes.util.find_library('wpcap')
            if pcap_lib_path:
                pcap_lib = ctypes.CDLL(pcap_lib_path)
            else:
                raise Exception("找不到wpcap.dll")
            
            # 定义函数
            pcap_open_live = pcap_lib.pcap_open_live
            pcap_open_live.argtypes = [
                ctypes.c_char_p,    # device
                ctypes.c_int,       # snaplen
                ctypes.c_int,       # promisc
                ctypes.c_int,       # to_ms
                ctypes.c_char_p     # errbuf
            ]
            pcap_open_live.restype = ctypes.c_void_p  # 返回handle指针
            
            # 调用函数
            errbuf = ctypes.create_string_buffer(256)
            handle = pcap_open_live(
                device_name.encode('utf-8'),
                self.snap_len,
                1 if self.promiscuous else 0,
                self.timeout_ms,
                errbuf
            )
            
            if not handle:
                error_msg = errbuf.value.decode('utf-8') if errbuf.value else "Unknown error"
                raise Exception(f"pcap_open_live失败: {error_msg}")
            
            # 创建一个简单的包装器对象
            class SimpleHandle:
                def __init__(self, handle_ptr):
                    self.handle = handle_ptr
                
                def next(self):
                    # 这里需要实现next()方法
                    # 这比较复杂，需要调用pcap_next等函数
                    # 为简化，这里返回None
                    return None
                
                def close(self):
                    # 调用pcap_close
                    pass
            
            return SimpleHandle(handle)
            
        except Exception as e:
            print(f"直接打开设备失败: {e}")
            return None
    
    def _set_filter(self, handle, filter_expr):
        """设置BPF过滤器"""
        # 这需要根据handle的类型来实现
        # 由于有多种handle类型，这里留空
        pass
    
    def _npcap_capture_loop(self):
        """Npcap捕获循环"""
        # 由于打开设备的复杂性，这里先实现一个基本版本
        # 实际实现需要根据具体的handle类型来调整
        print("Npcap捕获循环已启动，但可能无法捕获数据包")
        print("这是因为当前winpcapy版本的API结构与标准不同")
        
        while self.is_running:
            time.sleep(1)
            # 这里需要实现实际的捕获逻辑
            # 但由于handle类型的复杂性，暂时留空
    
    def _start_raw_socket_capture(self):
        """回退: 使用原始套接字启动捕获"""
        print("Starting capture using raw sockets...")
        
        # 这只是一个占位符 - 我们应该实现一个真正的回退
        # 目前，我们只打印一个错误消息
        print("原始套接字捕获未实现")
        print("请安装Npcap以启用数据包捕获")
        return False
    
    def stop_capture(self):
        """停止数据包捕获"""
        if not self.is_running:
            return
        
        print("停止捕获...")
        self.is_running = False
        
        # 等待线程完成
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
            self.capture_thread = None
        
        # 关闭句柄
        for handle, device_name in self.pcap_handles:
            try:
                if hasattr(handle, 'close'):
                    handle.close()
                else:
                    # 某些winpcapy版本可能使用不同方法
                    pass
            except Exception as e:
                print(f"关闭设备 {device_name} 出错: {e}")
        
        self.pcap_handles = []
        
        print(f"捕获已停止。统计: {self.stats}")
    
    def _process_packet(self, packet_data):
        """处理捕获的数据包并提取相关信息"""
        try:
            # 确保有足够的数据用于IP头
            if len(packet_data) < 20:
                return None
            
            # 解析IP头（IPv4的前20字节）
            ip_header = packet_data[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            
            # 如果不是IPv4则跳过
            if version != 4:
                return None
                
            iph_length = ihl * 4
            ttl = iph[5]
            protocol = iph[6]
            src_addr = socket.inet_ntoa(iph[8])
            dst_addr = socket.inet_ntoa(iph[9])
            
            # 基本数据包信息
            packet_info = {
                'version': version,
                'ihl': ihl,
                'ttl': ttl,
                'protocol': protocol,
                'src_ip': src_addr,
                'dst_ip': dst_addr,
                'length': len(packet_data)
            }
            
            # 解析传输层
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
            # 静默忽略数据包处理错误
            return None
    
    def get_packet(self, block=True, timeout=None):
        """从队列中获取数据包"""
        try:
            return self.packet_queue.get(block=block, timeout=timeout)
        except queue.Empty:
            return None
    
    def get_queue_size(self):
        """获取数据包队列的当前大小"""
        return self.packet_queue.qsize()
    
    def get_stats(self):
        """获取当前捕获统计信息"""
        return self.stats.copy()


# 创建别名以与现有代码兼容
Capture = WinPcapClassCapture