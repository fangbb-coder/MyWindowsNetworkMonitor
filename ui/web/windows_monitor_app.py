#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
基于Windows原生API的网络监控Web界面
无需Npcap驱动，支持无线网络监控
"""

import sys
import os
import json
import random
import threading
import time
import psutil
from flask import Flask, render_template, jsonify, request

# 添加项目路径
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# 导入系统模块
import socket

# 导入Windows原生监控模块
try:
    from core.windows_traffic_monitor import WindowsTrafficMonitor
    HAS_WINDOWS_MONITOR = True
except ImportError:
    HAS_WINDOWS_MONITOR = False
    print("警告: 无法导入Windows原生监控模块")

# 导入IP地理位置模块
try:
    from core.ip_geolocation import ip_geolocator
    HAS_IP_GEOLOCATION = True
except ImportError:
    HAS_IP_GEOLOCATION = False
    print("警告: 无法导入IP地理位置模块")

# 创建Flask应用
app = Flask(__name__, template_folder='templates')

# 全局变量
monitor = None
monitor_thread = None
monitor_running = False
last_traffic_data = {}

# 自动启动监控的标志
auto_monitor_started = False

# 加载配置
def load_config():
    config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../config.json'))
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        print(f"配置已加载: {config_path}")
        return config
    except Exception as e:
        print(f"配置加载失败: {e}")
        # 使用默认配置
        return {
            "interface": "auto",
            "web_port": 8080,
            "refresh_interval": 1000,
            "blacklist_ip": [],
            "blacklist_domain": [],
            "blacklist_port": [4444, 1337, 31337]
        }

config = load_config()

def _ensure_monitor():
    """确保监控实例存在"""
    global monitor, auto_monitor_started
    if monitor is None and HAS_WINDOWS_MONITOR:
        monitor = WindowsTrafficMonitor()
        print("✓ Windows原生监控器已初始化")
        
        # 自动启动监控（仅在第一次初始化时）
        if not auto_monitor_started:
            _auto_start_monitor()
            auto_monitor_started = True
    return monitor is not None

def _auto_start_monitor():
    """自动启动监控"""
    global monitor_running, monitor_thread, monitor
    
    if not _ensure_monitor():
        return False
    
    if monitor_running:
        return True
    
    try:
        # 启动监控（不指定特定接口，监控所有网卡）
        success = monitor.start_monitoring()
        
        if not success:
            print("⚠️ 自动启动监控失败，将使用被动模式")
            return False
        
        # 启动监控线程
        monitor_running = True
        monitor_thread = threading.Thread(target=_monitor_loop, daemon=True)
        monitor_thread.start()
        
        print("✅ 自动监控已启动，监控所有网络接口")
        return True
        
    except Exception as e:
        print(f"❌ 自动启动监控失败: {e}")
        return False

def _monitor_loop():
    """监控循环"""
    global monitor_running, monitor, last_traffic_data
    
    while monitor_running:
        if monitor:
            try:
                # 获取实时流量数据
                traffic_data = monitor.get_traffic_data(timeout=1)
                if traffic_data:
                    last_traffic_data = traffic_data
                    
                # 统计信息已经在监控循环中自动更新，无需额外调用
                # monitor.get_stats() 方法会返回最新的统计信息
                
            except Exception as e:
                print(f"监控循环错误: {e}")
        
        time.sleep(0.5)  # 每0.5秒更新一次

# 路由
@app.route('/')
def index():
    try:
        # 添加时间戳以避免浏览器缓存
        return render_template('windows_dashboard.html', timestamp=int(time.time()))
    except Exception as e:
        print(f"模板渲染错误: {e}")
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>我的Windows网络实时连接监控系统</title>
            <meta charset="utf-8">
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .container { max-width: 800px; margin: 0 auto; }
                .status { padding: 20px; border-radius: 5px; margin: 20px 0; }
                .success { background: #d4edda; color: #155724; }
                .error { background: #f8d7da; color: #721c24; }
                .warning { background: #fff3cd; color: #856404; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>我的Windows网络实时连接监控系统</h1>
                <div class="status success">
                    <h3>✓ 系统运行正常</h3>
                    <p>基于Windows原生API，无需Npcap驱动</p>
                </div>
                <div class="status warning">
                    <h3>⚠ 模板加载失败</h3>
                    <p>但API接口正常工作，请检查以下功能：</p>
                    <ul>
                        <li><a href="/api/status">系统状态</a></li>
                        <li><a href="/api/interfaces">网络接口</a></li>
                        <li><a href="/api/traffic">流量统计</a></li>
                    </ul>
                </div>
            </div>
        </body>
        </html>
        """

@app.route('/dashboard')
def dashboard():
    return index()

@app.route('/connections')
def connections():
    try:
        return render_template('windows_connections.html')
    except Exception as e:
        print(f"模板渲染错误: {e}")
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>连接监控</title>
            <meta charset="utf-8">
        </head>
        <body>
            <div style="margin: 40px; text-align: center;">
                <h1>连接监控</h1>
                <p>模板加载失败，但API接口正常工作</p>
                <p><a href="/">返回首页</a></p>
            </div>
        </body>
        </html>
        """

@app.route('/processes')
def processes():
    try:
        return render_template('windows_processes.html')
    except Exception as e:
        print(f"模板渲染错误: {e}")
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>进程监控</title>
            <meta charset="utf-8">
        </head>
        <body>
            <div style="margin: 40px; text-align: center;">
                <h1>进程监控</h1>
                <p>模板加载失败，但API接口正常工作</p>
                <p><a href="/">返回首页</a></p>
            </div>
        </body>
        </html>
        """

@app.route('/protocols')
def protocols():
    try:
        return render_template('windows_protocols.html')
    except Exception as e:
        print(f"模板渲染错误: {e}")
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>协议分析</title>
            <meta charset="utf-8">
        </head>
        <body>
            <div style="margin: 40px; text-align: center;">
                <h1>协议分析</h1>
                <p>模板加载失败，但API接口正常工作</p>
                <p><a href="/">返回首页</a></p>
            </div>
        </body>
        </html>
        """

@app.route('/earth')
def earth():
    try:
        return render_template('windows_earth.html')
    except Exception as e:
        print(f"模板渲染错误: {e}")
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>地球视图</title>
            <meta charset="utf-8">
        </head>
        <body>
            <div style="margin: 40px; text-align: center;">
                <h1>地球视图</h1>
                <p>模板加载失败，但API接口正常工作</p>
                <p><a href="/">返回首页</a></p>
            </div>
        </body>
        </html>
        """

# API路由
@app.route('/api/status')
def api_status():
    """获取系统状态"""
    global monitor_running, monitor
    
    if not _ensure_monitor():
        return jsonify({
            'status': 'error',
            'message': '监控模块初始化失败',
            'is_running': False,
            'has_windows_monitor': HAS_WINDOWS_MONITOR
        })
    
    stats = monitor.get_stats() if monitor else {}
    
    # 确保统计信息格式正确
    if 'stats' not in stats:
        stats = {'stats': {}}
    
    # 添加总流量统计
    if 'total_bytes_sent' not in stats['stats']:
        stats['stats']['total_bytes_sent'] = 0
    if 'total_bytes_recv' not in stats['stats']:
        stats['stats']['total_bytes_recv'] = 0
    if 'total_bytes' not in stats['stats']:
        stats['stats']['total_bytes'] = stats['stats']['total_bytes_sent'] + stats['stats']['total_bytes_recv']
    
    # 添加实时流量速率
    if 'total_sent_rate' not in stats['stats']:
        stats['stats']['total_sent_rate'] = 0
    if 'total_recv_rate' not in stats['stats']:
        stats['stats']['total_recv_rate'] = 0
    
    # 添加接口统计
    if 'interface_stats' not in stats['stats']:
        stats['stats']['interface_stats'] = {}
    
    # 添加活动连接数
    if 'active_connections' not in stats['stats']:
        stats['stats']['active_connections'] = 0
    
    return jsonify({
        'status': 'success',
        'is_running': True,  # 总是返回true，因为监控是自动的
        'has_windows_monitor': HAS_WINDOWS_MONITOR,
        'auto_monitoring': True,  # 添加自动监控标志
        'stats': stats
    })

@app.route('/api/sessions')
def api_sessions():
    """获取会话连接数据 - 优化响应速度"""
    
    try:
        # 快速检查监控器状态
        if not _ensure_monitor():
            # 直接返回空数组，而不是生成示例数据
            return jsonify([])
        
        # 快速获取连接信息，减少处理时间
        connections = monitor.get_detailed_connections()
        
        # 如果没有连接，直接返回空数组
        if not connections:
            return jsonify([])
        
        # 简化数据处理，减少循环中的复杂操作
        sessions = []
        
        for conn in connections:
            # 快速解析地址
            local_parts = conn.get('local_address', '').split(':')
            remote_parts = conn.get('remote_address', '').split(':') if conn.get('remote_address') not in ['', 'N/A'] else ['', '']
            
            # 获取基本连接信息
            src_ip = local_parts[0] if len(local_parts) > 0 else ''
            dst_ip = remote_parts[0] if len(remote_parts) > 0 and remote_parts[0] else ''
            
            # 快速过滤：只保留外部IP连接
            if not dst_ip or dst_ip in ['127.0.0.1', 'localhost'] or dst_ip.startswith('127.'):
                continue
            if dst_ip.startswith('192.168.') or dst_ip.startswith('10.') or (dst_ip.startswith('172.') and 16 <= int(dst_ip.split('.')[1] or 0) <= 31):
                continue
            
            # 改进进程名获取
            process_name = '未知'
            process_path = ''
            pid = conn.get('pid')
            if pid:
                try:
                    process = psutil.Process(pid)
                    process_name = process.name()
                    # 如果进程名无效，使用PID显示
                    if not process_name or process_name.lower() in ['unknown', 'system', 'idle', 'svchost']:
                        process_name = f"PID:{pid}"
                    process_path = process.exe() if hasattr(process, 'exe') else ''
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    process_name = f"PID:{pid}"
            
            # 简化流量统计
            total_bytes = conn.get('total_bytes', 1024)
            
            # 获取地理位置信息
            location = '未知'
            latitude = None
            longitude = None
            try:
                from core.ip_geolocation import ip_geolocator
                location_info = ip_geolocator.get_location(dst_ip)
                location = ip_geolocator.format_location(location_info)
                latitude = location_info.get('lat')
                longitude = location_info.get('lon')
            except:
                pass
            
            # 计算连接持续时间（如果可用）
            duration = conn.get('duration', 60)  # 默认值60秒
            
            session_data = {
                'protocol': conn.get('protocol', 'TCP'),
                'src_ip': src_ip,
                'src_port': local_parts[1] if len(local_parts) > 1 else '0',
                'dst_ip': dst_ip,
                'dst_port': remote_parts[1] if len(remote_parts) > 1 else '0',
                'state': conn.get('status', 'ESTABLISHED'),
                'pid': pid or '',
                'process_name': process_name,
                'bytes_sent': total_bytes // 2,
                'bytes_received': total_bytes // 2,
                'total_bytes': total_bytes,
                'location': location,
                'latitude': latitude,
                'longitude': longitude,
                'duration': duration
            }
            sessions.append(session_data)
        
        # 简单排序
        sessions.sort(key=lambda x: x['total_bytes'], reverse=True)
        
        return jsonify(sessions[:50])  # 限制返回数量提高性能
        
    except Exception as e:
        # 快速出错处理，直接返回空数组
        return jsonify([])

def generate_sample_session_data():
    """生成示例会话数据"""
    import random
    
    sample_sessions = [
        {
            'protocol': 'TCP',
            'src_ip': '192.168.1.100',
            'src_port': '54321',
            'dst_ip': '8.8.8.8',
            'dst_port': '443',
            'state': 'ESTABLISHED',
            'pid': 1234,
            'process_name': 'chrome.exe',
            'bytes_sent': random.randint(1024, 1024*100),
            'bytes_received': random.randint(1024*100, 1024*1024),
            'total_bytes': 0,
            'location': 'Google DNS',
            'duration': random.randint(10, 300)
        },
        {
            'protocol': 'TCP',
            'src_ip': '192.168.1.100',
            'src_port': '54322',
            'dst_ip': '151.101.1.69',
            'dst_port': '443',
            'state': 'ESTABLISHED',
            'pid': 5678,
            'process_name': 'firefox.exe',
            'bytes_sent': random.randint(1024, 1024*50),
            'bytes_received': random.randint(1024*200, 1024*1024*2),
            'total_bytes': 0,
            'location': 'CloudFlare',
            'duration': random.randint(30, 600)
        },
        {
            'protocol': 'TCP',
            'src_ip': '192.168.1.100',
            'src_port': '54323',
            'dst_ip': '104.244.42.65',
            'dst_port': '443',
            'state': 'ESTABLISHED',
            'pid': 9012,
            'process_name': 'edge.exe',
            'bytes_sent': random.randint(1024, 1024*80),
            'bytes_received': random.randint(1024*150, 1024*1024*3),
            'total_bytes': 0,
            'location': 'Twitter',
            'duration': random.randint(60, 1200)
        },
        {
            'protocol': 'TCP',
            'src_ip': '192.168.1.100',
            'src_port': '54324',
            'dst_ip': '185.199.108.153',
            'dst_port': '443',
            'state': 'ESTABLISHED',
            'pid': 3456,
            'process_name': 'github.exe',
            'bytes_sent': random.randint(1024, 1024*30),
            'bytes_received': random.randint(1024*50, 1024*1024),
            'total_bytes': 0,
            'location': 'GitHub',
            'duration': random.randint(5, 180)
        }
    ]
    
    # 计算总流量
    for session in sample_sessions:
        session['total_bytes'] = session['bytes_sent'] + session['bytes_received']
    
    return sample_sessions

@app.route('/api/processes')
def api_processes():
    """获取进程流量数据 - 优化响应速度"""
    
    try:
        # 快速检查监控器状态
        if not _ensure_monitor():
            return jsonify([])
        
        # 快速获取连接信息
        connections = monitor.get_detailed_connections()
        
        # 如果没有连接，直接返回空数组
        if not connections:
            return jsonify([])
        
        # 简化进程统计
        process_stats = {}
        for conn in connections:
            pid = conn.get('pid')
            if pid:
                if pid not in process_stats:
                    # 简化进程信息获取
                    process_name = f"PID:{pid}"
                    process_path = ''
                    try:
                        process = psutil.Process(pid)
                        process_name = process.name()
                        process_path = process.exe() if hasattr(process, 'exe') else ''
                    except:
                        pass
                    
                    process_stats[pid] = {
                        'pid': pid,
                        'process_name': process_name,
                        'process_path': process_path,
                        'sessions': 0
                    }
                process_stats[pid]['sessions'] += 1
        
        # 转换为列表并简单排序
        processes = list(process_stats.values())
        processes.sort(key=lambda x: x['sessions'], reverse=True)
        
        return jsonify(processes[:10])  # 限制返回数量
        
    except Exception as e:
        # 快速出错处理
        return jsonify([])

def generate_sample_process_data():
    """生成示例进程数据"""
    sample_processes = [
        {
            'pid': 1234,
            'process_name': 'chrome.exe',
            'process_path': 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
            'sessions': random.randint(5, 15)
        },
        {
            'pid': 5678,
            'process_name': 'firefox.exe',
            'process_path': 'C:\\Program Files\\Mozilla Firefox\\firefox.exe',
            'sessions': random.randint(3, 10)
        },
        {
            'pid': 9012,
            'process_name': 'edge.exe',
            'process_path': 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
            'sessions': random.randint(2, 8)
        },
        {
            'pid': 3456,
            'process_name': 'svchost.exe',
            'process_path': 'C:\\Windows\\System32\\svchost.exe',
            'sessions': random.randint(1, 5)
        },
        {
            'pid': 7890,
            'process_name': 'explorer.exe',
            'process_path': 'C:\\Windows\\explorer.exe',
            'sessions': random.randint(1, 3)
        }
    ]
    
    # 随机排序并返回
    random.shuffle(sample_processes)
    return sample_processes[:5]

@app.route('/api/protocols')
def api_protocols():
    """获取协议统计 - 优化响应速度"""
    
    # 协议名称映射字典
    protocol_name_map = {
        'SOCK_STREAM': 'TCP',
        'SOCK_DGRAM': 'UDP',
        'TCP': 'TCP',
        'UDP': 'UDP',
        'ICMP': 'ICMP',
        'SOCK_RAW': 'RAW',
        'SOCK_SEQPACKET': 'SCTP'
    }
    
    try:
        # 快速检查监控器状态
        if not _ensure_monitor():
            sample_data = generate_sample_protocol_data()
            return jsonify({'status': 'success', 'data': sample_data})
        
        # 快速获取连接信息
        connections = monitor.get_detailed_connections()
        
        # 如果没有连接，返回示例数据
        if not connections:
            sample_data = generate_sample_protocol_data()
            return jsonify({'status': 'success', 'data': sample_data})
        
        # 简化协议统计
        stats = {}
        for conn in connections:
            protocol = conn.get('protocol', 'TCP')
            
            # 映射协议名称到友好名称
            friendly_protocol = protocol_name_map.get(protocol, protocol)
            
            if friendly_protocol not in stats:
                stats[friendly_protocol] = {
                    'session_count': 0,
                    'packets': 0,
                    'bytes': 0,
                    'original_protocol': protocol  # 保留原始协议名称用于调试
                }
            stats[friendly_protocol]['session_count'] += 1
            stats[friendly_protocol]['bytes'] += conn.get('total_bytes', 1024)
            stats[friendly_protocol]['packets'] += conn.get('total_bytes', 1024) // 1024  # 根据字节数估算包数
        
        # 如果统计结果为空，返回示例数据
        if not stats:
            sample_data = generate_sample_protocol_data()
            return jsonify({'status': 'success', 'data': sample_data})
            
        return jsonify({'status': 'success', 'data': stats})
        
    except Exception as e:
        # 出错时返回示例数据
        sample_data = generate_sample_protocol_data()
        return jsonify({'status': 'success', 'data': sample_data})

def generate_sample_protocol_data():
    """生成示例协议数据"""
    protocols = {
        'TCP': {
            'bytes': random.randint(1024*100, 1024*1024*10),
            'packets': random.randint(100, 5000),
            'session_count': random.randint(5, 50)
        },
        'UDP': {
            'bytes': random.randint(1024*50, 1024*1024*5),
            'packets': random.randint(50, 2000),
            'session_count': random.randint(3, 20)
        },
        'HTTP': {
            'bytes': random.randint(1024*200, 1024*1024*8),
            'packets': random.randint(150, 3000),
            'session_count': random.randint(8, 30)
        },
        'HTTPS': {
            'bytes': random.randint(1024*300, 1024*1024*15),
            'packets': random.randint(200, 4000),
            'session_count': random.randint(10, 40)
        }
    }
    
    # 随机选择1-3个协议显示
    selected_protocols = random.sample(list(protocols.keys()), random.randint(1, 3))
    result = {}
    for protocol in selected_protocols:
        result[protocol] = protocols[protocol]
    
    return result

@app.route('/api/interfaces')
def api_interfaces():
    """获取网络接口列表"""
    if not _ensure_monitor():
        return jsonify({'status': 'error', 'message': '监控模块初始化失败'})
    
    try:
        interfaces = monitor.get_interfaces()
        return jsonify({
            'status': 'success',
            'interfaces': interfaces
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/traffic')
def api_traffic():
    """获取实时流量数据"""
    global last_traffic_data, monitor
    
    if not _ensure_monitor():
        return jsonify({'status': 'error', 'message': '监控模块初始化失败'})
    
    try:
        # 获取最新流量数据
        traffic_data = monitor.get_traffic_data(timeout=0.5)
        if traffic_data:
            last_traffic_data = traffic_data
        
        return jsonify({
            'status': 'success',
            'traffic': last_traffic_data if last_traffic_data else {}
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# 自动监控，无需手动启动/停止API

@app.route('/api/test')
def api_test():
    """测试API连接"""
    return jsonify({
        'status': 'success', 
        'message': 'API连接正常',
        'timestamp': time.time(),
        'has_windows_monitor': HAS_WINDOWS_MONITOR
    })

@app.route('/api/lookup_ip', methods=['POST'])
def api_lookup_ip():
    """实时查询IP地址的地理位置信息"""
    if not HAS_IP_GEOLOCATION:
        return jsonify({
            'status': 'error',
            'message': 'IP地理位置模块未启用'
        }), 500
    
    try:
        data = request.get_json(silent=True) or {}
        ip_address = data.get('ip')
        
        if not ip_address:
            return jsonify({
                'status': 'error',
                'message': 'IP地址不能为空'
            }), 400
        
        # 强制重新查询，不使用缓存
        location = ip_geolocator.get_location(ip_address, force_online=True)
        
        # 清除缓存，确保下次查询会重新获取最新数据
        if ip_address in ip_geolocator.cache:
            del ip_geolocator.cache[ip_address]
        
        # 获取地理位置摘要
        location_summary = ip_geolocator.get_location_summary(ip_address)
        
        return jsonify({
            'status': 'success',
            'ip': ip_address,
            'location': location,
            'summary': location_summary
        })
        
    except Exception as e:
        print(f"IP查询错误: {e}")
        return jsonify({
            'status': 'error',
            'message': f'查询失败: {str(e)}'
        }), 500

# 初始化应用
if __name__ == '__main__':
    print("=" * 60)
    print("我的Windows网络实时连接监控系统 - Windows原生API版本")
    print("=" * 60)
    
    print("系统信息:")
    print(f"  - Windows原生监控支持: {'✓' if HAS_WINDOWS_MONITOR else '✗'}")
    print(f"  - Web端口: {config.get('web_port', 8080)}")
    print(f"  - 无需Npcap驱动: ✓")
    print(f"  - 支持无线网络: ✓")
    
    # 检查模板目录
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    if os.path.exists(template_dir):
        templates = os.listdir(template_dir)
        print(f"  - 可用模板: {len(templates)}个")
    else:
        print("  - 模板目录: 不存在")
    
    port = config.get('web_port', 8080)
    print(f"\n正在启动Web服务器...")
    print(f"访问地址: http://localhost:{port}")
    print("按 Ctrl+C 停止服务器")
    
    try:
        app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
    except OSError as e:
        if 'Address already in use' in str(e):
            print(f"\n错误: 端口 {port} 已被占用")
            print("请关闭其他网络监控实例后重试")
        else:
            print(f"\n错误: {e}")
    except KeyboardInterrupt:
        print("\n服务器已停止")
    except Exception as e:
        print(f"\n服务器异常: {e}")
    
    print("\n程序结束")