"""
简化的数据包捕获模块
使用直接DLL调用方式，兼容所有winpcapy版本
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

class SimpleCapture:
    def __init__(self, interface='auto', filter_expr='', buffer_size=10000):
        self.interface = interface
        self.filter_expr = filter_expr
        self.buffer_size = buffer_size
        self.packet_queue = queue.Queue(maxsize=buffer_size)
        self.is_running = False
        self.capture_thread = None
        self.pcap_handle = None
        self.device_name = None
        
        # 统计信息
        self.stats = {
            'packets_captured': 0,
            'packets_dropped': 0,
            'bytes_captured': 0,
            'start_time': None
        }
        
        # Npcap设置
        self.snap_len = 65535  # 完整数据包
        self.promiscuous = True  # 混杂模式
        self.timeout_ms = 1000  # 1秒超时
        
        # 尝试加载wpcap.dll
        self.pcap_lib = self._load_pcap_dll()
    
    def _load_pcap_dll(self):
        """加载wpcap.dll"""
        try:
            # 尝试找到wpcap.dll
            import ctypes.util
            pcap_lib_path = ctypes.util.find_library('wpcap')
            
            if not pcap_lib_path:
                # 尝试常见路径
                common_paths = [
                    r'C:\Windows\System32\wpcap.dll',
                    r'C:\Windows\SysWOW64\wpcap.dll',
                    os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Npcap', 'wpcap.dll'),
                    os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'), 'Npcap', 'wpcap.dll'),
                ]
                
                for path in common_paths:
                    if os.path.exists(path):
                        pcap_lib_path = path
                        break
            
            if not pcap_lib_path:
                print("找不到wpcap.dll，请确保已安装Npcap")
                return None
            
            pcap_lib = ctypes.CDLL(pcap_lib_path)
            print(f"成功加载wpcap.dll: {pcap_lib_path}")
            return pcap_lib
            
        except Exception as e:
            print(f"加载wpcap.dll失败: {e}")
            return None
    
    def check_admin_privileges(self):
        """检查管理员权限"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    
    def check_npcap_installed(self):
        """检查Npcap是否正确安装"""
        return self.pcap_lib is not None
    
    def get_interfaces(self):
        """获取所有可用的网络接口"""
        # 使用简化方法，直接返回psutil接口信息
        return self._get_simple_interfaces()
    
    def _get_simple_interfaces(self):
        """简化方法：直接使用psutil获取接口信息"""
        interfaces = []
        
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            for name, addr_list in addrs.items():
                # 检查接口是否活动
                is_up = True
                if name in stats:
                    is_up = stats[name].isup
                
                # 查找IPv4地址
                ip_address = 'N/A'
                netmask = ''
                for addr in addr_list:
                    if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                        ip_address = addr.address
                        netmask = addr.netmask
                        break
                
                # 生成简单的设备描述
                description = name
                name_lower = name.lower()
                
                if 'wi-fi' in name_lower or 'wifi' in name_lower or 'wlan' in name_lower:
                    description = f"WiFi Adapter - {name}"
                elif 'ethernet' in name_lower:
                    description = f"Ethernet Adapter - {name}"
                elif 'realtek' in name_lower:
                    description = f"Realtek Adapter - {name}"
                elif 'intel' in name_lower:
                    description = f"Intel Adapter - {name}"
                
                # 生成简单的Npcap设备名称
                npcap_device = f"\\Device\\NPF_{{{name.replace(' ', '_')}}}"
                
                interfaces.append({
                    'name': name,
                    'description': description,
                    'ip': ip_address,
                    'netmask': netmask,
                    'is_up': is_up,
                    'npcap_device': npcap_device
                })
                
            print(f"成功找到 {len(interfaces)} 个网络接口")
            return interfaces
                
        except Exception as e:
            print(f"获取接口信息失败: {e}")
            return []
    
    def _get_interfaces_fallback(self):
        """回退方法：不使用Npcap获取接口"""
        interfaces = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            for name, addr_list in addrs.items():
                # 检查接口是否活动
                if name in stats and not stats[name].isup:
                    continue
                
                # 查找IPv4地址
                ip_address = 'N/A'
                for addr in addr_list:
                    if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                        ip_address = addr.address
                        break
                
                # 添加接口，即使没有IPv4地址也要显示
                interfaces.append({
                    'name': name,
                    'description': name,
                    'ip': ip_address,
                    'netmask': addr.netmask if ip_address != 'N/A' else 'N/A',
                    'is_up': stats[name].isup if name in stats else True,
                    'npcap_device': f"\\Device\\NPF_{{{name}}}"  # 生成类似Npcap的设备名称
                })
        except Exception as e:
            print(f"回退接口检测失败: {e}")
        
        return interfaces
    
    def start_capture(self, interface_ip=None):
        """启动数据包捕获"""
        if self.is_running:
            print("捕获已在运行")
            return True
        
        # 更新接口
        if interface_ip:
            self.interface = interface_ip
        
        if not self.pcap_lib:
            print("wpcap.dll未加载，无法启动捕获")
            return False
        
        return self._start_pcap_capture()
    
    def _start_pcap_capture(self):
        """使用pcap DLL启动捕获"""
        print("启动Npcap捕获...")
        
        try:
            # 检查管理员权限
            if not self.check_admin_privileges():
                print("警告: 未以管理员身份运行，捕获可能失败")
            
            # 获取所有接口
            interfaces = self.get_interfaces()
            if not interfaces:
                print("未找到接口")
                return False
            
            print(f"找到 {len(interfaces)} 个接口:")
            for i, iface in enumerate(interfaces):
                print(f"  {i+1}. {iface['name']} -> {iface['npcap_device']} (IP: {iface['ip']}, UP: {iface['is_up']})")
            
            # 找到要捕获的接口
            device_to_capture = None
            
            if self.interface == 'auto':
                # 自动选择第一个有效的活动接口（排除VMware和虚拟接口）
                up_interfaces = [i for i in interfaces if i.get('is_up', True)]
                
                # 优先选择真实的网络接口（排除VMware、虚拟接口等）
                valid_interfaces = []
                for iface in up_interfaces:
                    name_lower = iface['name'].lower()
                    # 排除VMware和虚拟接口
                    if 'vmware' in name_lower or 'virtual' in name_lower or 'loopback' in name_lower:
                        continue
                    # 优先选择有实际IP地址的接口
                    if iface['ip'] != 'N/A' and iface['ip'] != '127.0.0.1':
                        valid_interfaces.append(iface)
                
                if valid_interfaces:
                    device_to_capture = valid_interfaces[0]
                    print(f"自动选择有效接口: {device_to_capture['name']}")
                elif up_interfaces:
                    # 如果没有有效的，选择第一个活动的
                    device_to_capture = up_interfaces[0]
                    print(f"自动选择接口: {device_to_capture['name']}")
                else:
                    print("没有活动的接口")
            else:
                # 尝试匹配IP或名称
                print(f"尝试匹配接口: {self.interface}")
                for iface in interfaces:
                    print(f"  检查: {iface['name']} (IP: {iface['ip']})")
                    if (iface['ip'] == self.interface or 
                        self.interface in iface['name'] or 
                        iface['name'] in self.interface):
                        device_to_capture = iface
                        print(f"匹配到接口: {iface['name']}")
                        break
                
                # 如果没有匹配，尝试使用接口名称
                if not device_to_capture:
                    print("尝试匹配Npcap设备名称...")
                    for iface in interfaces:
                        if self.interface in iface['npcap_device'] or iface['npcap_device'] in self.interface:
                            device_to_capture = iface
                            print(f"通过Npcap设备名称匹配到接口: {iface['name']}")
                            break
            
            if not device_to_capture:
                print("未找到匹配的接口")
                return False
            
            self.device_name = device_to_capture['npcap_device']
            print(f"尝试打开设备: {self.device_name}")
            
            # 定义pcap_open_live函数
            pcap_open_live = self.pcap_lib.pcap_open_live
            pcap_open_live.argtypes = [
                ctypes.c_char_p,    # device
                ctypes.c_int,       # snaplen
                ctypes.c_int,       # promisc
                ctypes.c_int,       # to_ms
                ctypes.c_char_p     # errbuf
            ]
            pcap_open_live.restype = ctypes.c_void_p  # 返回handle指针
            
            # 定义pcap_next函数
            pcap_next = self.pcap_lib.pcap_next
            pcap_next.argtypes = [
                ctypes.c_void_p,     # handle
                ctypes.c_void_p      # header
            ]
            pcap_next.restype = ctypes.c_void_p  # 返回数据包指针
            
            # 定义pcap_close函数
            pcap_close = self.pcap_lib.pcap_close
            pcap_close.argtypes = [ctypes.c_void_p]
            pcap_close.restype = None
            
            # 调用pcap_open_live
            errbuf = ctypes.create_string_buffer(256)
            
            # 尝试多种参数组合来绕过安全限制
            parameter_combinations = [
                # 标准参数
                (self.snap_len, 1 if self.promiscuous else 0, self.timeout_ms),
                # 非混杂模式
                (self.snap_len, 0, self.timeout_ms),
                # 较小的snap_len
                (1514, 1 if self.promiscuous else 0, self.timeout_ms),
                # 非混杂模式 + 较小snap_len
                (1514, 0, self.timeout_ms),
                # 增加超时时间
                (self.snap_len, 1 if self.promiscuous else 0, 5000),
            ]
            
            for i, (snap_len, promisc, timeout) in enumerate(parameter_combinations):
                print(f"尝试参数组合 {i+1}: snap_len={snap_len}, promisc={promisc}, timeout={timeout}")
                self.pcap_handle = pcap_open_live(
                    self.device_name.encode('utf-8', errors='ignore'),
                    snap_len,
                    promisc,
                    timeout,
                    errbuf
                )
                
                if self.pcap_handle:
                    print(f"成功打开设备: {self.device_name} (使用参数组合 {i+1})")
                    # 更新实际使用的参数
                    self.snap_len = snap_len
                    self.promiscuous = promisc
                    self.timeout_ms = timeout
                    break
            
            if not self.pcap_handle:
                # 如果所有参数组合都失败，尝试使用pcap_create + pcap_activate
                print("尝试使用pcap_create + pcap_activate方法...")
                try:
                    # 查找pcap_create函数
                    pcap_create = getattr(self.pcap_lib, 'pcap_create', None)
                    pcap_activate = getattr(self.pcap_lib, 'pcap_activate', None)
                    
                    if pcap_create and pcap_activate:
                        # 设置函数签名
                        pcap_create.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                        pcap_create.restype = ctypes.c_void_p
                        
                        pcap_activate.argtypes = [ctypes.c_void_p]
                        pcap_activate.restype = ctypes.c_int
                        
                        # 尝试创建和激活
                        self.pcap_handle = pcap_create(
                            self.device_name.encode('utf-8', errors='ignore'),
                            errbuf
                        )
                        
                        if self.pcap_handle:
                            result = pcap_activate(self.pcap_handle)
                            if result == 0:
                                print(f"成功使用pcap_create激活设备: {self.device_name}")
                            else:
                                print(f"pcap_activate失败: {result}")
                                self.pcap_handle = None
                except Exception as e:
                    print(f"pcap_create方法失败: {e}")
            
            if not self.pcap_handle:
                try:
                    error_msg = errbuf.value.decode('utf-8', errors='ignore') if errbuf.value else "Unknown error"
                except:
                    error_msg = "Unknown error (encoding issue)"
                print(f"所有方法都失败: {error_msg}")
                return False
            
            print(f"成功打开设备: {self.device_name}")
            
            # 设置BPF过滤器（如果提供）
            if self.filter_expr:
                # 这里需要实现过滤器设置
                # 由于复杂性，暂时跳过
                print(f"注意: 过滤器设置尚未实现: {self.filter_expr}")
            
            # 启动捕获线程
            self.is_running = True
            self.stats['start_time'] = datetime.now()
            
            self.capture_thread = threading.Thread(target=self._pcap_capture_loop)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
            print("成功启动Npcap捕获")
            return True
            
        except Exception as e:
            print(f"启动Npcap捕获出错: {e}")
            return False
    
    def _pcap_capture_loop(self):
        """pcap捕获循环"""
        # 定义pcap_next函数
        pcap_next = self.pcap_lib.pcap_next
        pcap_next.argtypes = [
            ctypes.c_void_p,     # handle
            ctypes.c_void_p      # header
        ]
        pcap_next.restype = ctypes.c_void_p  # 返回数据包指针
        
        # 定义pcap结构
        class pcap_pkthdr(ctypes.Structure):
            _fields_ = [
                ('ts_sec', ctypes.c_uint32),
                ('ts_usec', ctypes.c_uint32),
                ('caplen', ctypes.c_uint32),
                ('len', ctypes.c_uint32)
            ]
        
        while self.is_running:
            try:
                # 创建数据包头结构
                header = pcap_pkthdr()
                
                # 获取下一个数据包
                packet_ptr = pcap_next(self.pcap_handle, ctypes.byref(header))
                
                if packet_ptr:
                    # 获取数据包长度
                    packet_len = header.caplen
                    
                    # 读取数据包内容
                    packet_data = ctypes.cast(packet_ptr, ctypes.POINTER(ctypes.c_ubyte * packet_len))
                    packet_bytes = bytes(packet_data.contents)
                    
                    self.stats['packets_captured'] += 1
                    self.stats['bytes_captured'] += packet_len
                    
                    # 处理数据包
                    packet_info = self._process_packet(packet_bytes)
                    
                    if packet_info:
                        # 添加到队列
                        if not self.packet_queue.full():
                            self.packet_queue.put(packet_info)
                        else:
                            self.stats['packets_dropped'] += 1
                
                # 短暂休眠避免CPU占用过高
                time.sleep(0.001)
                
            except Exception as e:
                if self.is_running:
                    print(f"捕获循环出错: {e}")
                time.sleep(0.01)
    
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
        if self.pcap_handle and self.pcap_lib:
            try:
                pcap_close = self.pcap_lib.pcap_close
                pcap_close.argtypes = [ctypes.c_void_p]
                pcap_close.restype = None
                pcap_close(self.pcap_handle)
                print("成功关闭pcap句柄")
            except Exception as e:
                print(f"关闭pcap句柄出错: {e}")
            finally:
                self.pcap_handle = None
        
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
Capture = SimpleCapture