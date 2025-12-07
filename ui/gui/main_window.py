from PyQt5.QtWidgets import (QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QPushButton, QTableWidget, QTableWidgetItem, 
                             QHeaderView, QProgressBar, QGroupBox, QGridLayout, 
                             QStatusBar, QAction, QMenu, QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QIcon, QFont
import sys
import os
import json

# Add the project root to the path so we can import core modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from core.capture import Capture
from core.session import SessionManager
from core.protocol import ProtocolAnalyzer
from core.process import get_pid_to_process_map

class PacketProcessingThread(QThread):
    """Thread for processing packets"""
    update_signal = pyqtSignal()
    
    def __init__(self, capture, session_manager, protocol_analyzer):
        super().__init__()
        self.capture = capture
        self.session_manager = session_manager
        self.protocol_analyzer = protocol_analyzer
        self.is_running = False
    
    def run(self):
        self.is_running = True
        while self.is_running:
            # Get a packet from the capture queue
            packet_info = self.capture.get_packet(block=True, timeout=1.0)
            
            if packet_info:
                # Process the packet and update the session
                session = self.session_manager.process_packet(packet_info)
                
                if session:
                    # Identify the application protocol
                    application_protocol = self.protocol_analyzer.identify_protocol(packet_info)
                    session.update_application_protocol(application_protocol)
                    
                    # Update protocol statistics
                    self.protocol_analyzer.update_protocol_stats(packet_info, application_protocol, session.id)
            
            # Cleanup old sessions
            self.session_manager.cleanup_old_sessions()
            
            # Emit update signal
            self.update_signal.emit()
    
    def stop(self):
        self.is_running = False

class DashboardTab(QWidget):
    """Dashboard tab showing real-time statistics"""
    def __init__(self, session_manager, protocol_analyzer):
        super().__init__()
        self.session_manager = session_manager
        self.protocol_analyzer = protocol_analyzer
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Stats grid
        stats_grid = QGridLayout()
        
        # Total sessions
        self.total_sessions_label = QLabel("0")
        self.total_sessions_label.setFont(QFont("Arial", 24, QFont.Bold))
        self.total_sessions_label.setAlignment(Qt.AlignCenter)
        stats_grid.addWidget(QLabel("总会话数"), 0, 0)
        stats_grid.addWidget(self.total_sessions_label, 1, 0)
        
        # TCP sessions
        self.tcp_sessions_label = QLabel("0")
        self.tcp_sessions_label.setFont(QFont("Arial", 24, QFont.Bold))
        self.tcp_sessions_label.setAlignment(Qt.AlignCenter)
        stats_grid.addWidget(QLabel("TCP会话"), 0, 1)
        stats_grid.addWidget(self.tcp_sessions_label, 1, 1)
        
        # UDP sessions
        self.udp_sessions_label = QLabel("0")
        self.udp_sessions_label.setFont(QFont("Arial", 24, QFont.Bold))
        self.udp_sessions_label.setAlignment(Qt.AlignCenter)
        stats_grid.addWidget(QLabel("UDP会话"), 0, 2)
        stats_grid.addWidget(self.udp_sessions_label, 1, 2)
        
        # Total traffic
        self.total_traffic_label = QLabel("0 MB")
        self.total_traffic_label.setFont(QFont("Arial", 24, QFont.Bold))
        self.total_traffic_label.setAlignment(Qt.AlignCenter)
        stats_grid.addWidget(QLabel("总流量"), 0, 3)
        stats_grid.addWidget(self.total_traffic_label, 1, 3)
        
        layout.addLayout(stats_grid)
        
        # Protocol stats group
        protocol_group = QGroupBox("协议统计")
        protocol_layout = QVBoxLayout()
        
        self.protocol_table = QTableWidget()
        self.protocol_table.setColumnCount(4)
        self.protocol_table.setHorizontalHeaderLabels(["协议", "数据包", "字节数", "会话数"])
        self.protocol_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        protocol_layout.addWidget(self.protocol_table)
        
        protocol_group.setLayout(protocol_layout)
        layout.addWidget(protocol_group)
        
        self.setLayout(layout)
    
    def update_stats(self):
        # Get session stats
        session_stats = self.session_manager.get_session_stats()
        
        # Update labels
        self.total_sessions_label.setText(str(session_stats['total_sessions']))
        self.tcp_sessions_label.setText(str(session_stats['tcp_sessions']))
        self.udp_sessions_label.setText(str(session_stats['udp_sessions']))
        
        total_traffic = (session_stats['total_traffic']['bytes_sent'] + 
                        session_stats['total_traffic']['bytes_received']) / (1024 * 1024)
        self.total_traffic_label.setText(f"{total_traffic:.2f} MB")
        
        # Update protocol table
        protocol_stats = self.protocol_analyzer.get_protocol_stats()
        self.protocol_table.setRowCount(len(protocol_stats))
        
        for row, (protocol, stats) in enumerate(protocol_stats.items()):
            self.protocol_table.setItem(row, 0, QTableWidgetItem(protocol))
            self.protocol_table.setItem(row, 1, QTableWidgetItem(str(stats['packets'])))
            self.protocol_table.setItem(row, 2, QTableWidgetItem(str(stats['bytes'])))
            self.protocol_table.setItem(row, 3, QTableWidgetItem(str(stats['session_count'])))

class ConnectionsTab(QWidget):
    """Connections tab showing all network connections"""
    def __init__(self, session_manager):
        super().__init__()
        self.session_manager = session_manager
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        self.connections_table = QTableWidget()
        self.connections_table.setColumnCount(10)
        self.connections_table.setHorizontalHeaderLabels([
            "协议", "源IP", "源端口", "目标IP", "目标端口", 
            "状态", "进程ID", "进程名", "上传字节", "下载字节"
        ])
        self.connections_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        layout.addWidget(self.connections_table)
        self.setLayout(layout)
    
    def update_connections(self):
        sessions = self.session_manager.get_all_sessions()
        self.connections_table.setRowCount(len(sessions))
        
        for row, session in enumerate(sessions):
            session_dict = session.to_dict()
            
            self.connections_table.setItem(row, 0, QTableWidgetItem(session_dict['protocol']))
            self.connections_table.setItem(row, 1, QTableWidgetItem(session_dict['src_ip']))
            self.connections_table.setItem(row, 2, QTableWidgetItem(str(session_dict['src_port'])))
            self.connections_table.setItem(row, 3, QTableWidgetItem(session_dict['dst_ip']))
            self.connections_table.setItem(row, 4, QTableWidgetItem(str(session_dict['dst_port'])))
            self.connections_table.setItem(row, 5, QTableWidgetItem(session_dict['state']))
            self.connections_table.setItem(row, 6, QTableWidgetItem(str(session_dict['pid']) if session_dict['pid'] else "-"))
            self.connections_table.setItem(row, 7, QTableWidgetItem(session_dict['process_name'] if session_dict['process_name'] else "-"))
            self.connections_table.setItem(row, 8, QTableWidgetItem(str(session_dict['bytes_sent'])))
            self.connections_table.setItem(row, 9, QTableWidgetItem(str(session_dict['bytes_received'])))

class ProcessesTab(QWidget):
    """Processes tab showing network traffic per process"""
    def __init__(self, session_manager):
        super().__init__()
        self.session_manager = session_manager
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        self.processes_table = QTableWidget()
        self.processes_table.setColumnCount(5)
        self.processes_table.setHorizontalHeaderLabels([
            "进程ID", "进程名", "上传字节", "下载字节", "总字节数"
        ])
        self.processes_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        layout.addWidget(self.processes_table)
        self.setLayout(layout)
    
    def update_processes(self):
        top_processes = self.session_manager.get_top_processes_by_traffic(limit=50)
        self.processes_table.setRowCount(len(top_processes))
        
        for row, process in enumerate(top_processes):
            self.processes_table.setItem(row, 0, QTableWidgetItem(str(process['pid'])))
            self.processes_table.setItem(row, 1, QTableWidgetItem(process['process_name']))
            self.processes_table.setItem(row, 2, QTableWidgetItem(str(process['bytes_sent'])))
            self.processes_table.setItem(row, 3, QTableWidgetItem(str(process['bytes_received'])))
            self.processes_table.setItem(row, 4, QTableWidgetItem(str(process['total_bytes'])))

class ProtocolsTab(QWidget):
    """Protocols tab showing protocol distribution"""
    def __init__(self, protocol_analyzer):
        super().__init__()
        self.protocol_analyzer = protocol_analyzer
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        self.protocols_table = QTableWidget()
        self.protocols_table.setColumnCount(4)
        self.protocols_table.setHorizontalHeaderLabels([
            "协议", "数据包", "字节数", "占比"
        ])
        self.protocols_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        layout.addWidget(self.protocols_table)
        self.setLayout(layout)
    
    def update_protocols(self):
        top_protocols = self.protocol_analyzer.get_top_protocols_by_traffic(limit=20)
        self.protocols_table.setRowCount(len(top_protocols))
        
        # Calculate total bytes for percentage
        total_bytes = sum(protocol['bytes'] for protocol in top_protocols)
        
        for row, protocol in enumerate(top_protocols):
            percentage = (protocol['bytes'] / total_bytes) * 100 if total_bytes > 0 else 0
            
            self.protocols_table.setItem(row, 0, QTableWidgetItem(protocol['protocol']))
            self.protocols_table.setItem(row, 1, QTableWidgetItem(str(protocol['packets'])))
            self.protocols_table.setItem(row, 2, QTableWidgetItem(str(protocol['bytes'])))
            self.protocols_table.setItem(row, 3, QTableWidgetItem(f"{percentage:.2f}%"))

class MainWindow(QMainWindow):
    """Main application window"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("网络监控工具")
        self.setGeometry(100, 100, 1200, 800)
        
        # Load configuration
        with open('../../config.json', 'r') as f:
            self.config = json.load(f)
        
        # Initialize core components
        self.capture = Capture(
            interface=self.config['interface'],
            filter_expr=self.config['packet_filter'],
            buffer_size=self.config['capture_buffer_size']
        )
        
        self.session_manager = SessionManager()
        self.protocol_analyzer = ProtocolAnalyzer()
        
        # Packet processing thread
        self.packet_thread = PacketProcessingThread(
            self.capture, self.session_manager, self.protocol_analyzer
        )
        self.packet_thread.update_signal.connect(self.update_ui)
        
        # Timer for UI updates
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_ui)
        self.update_timer.start(self.config['refresh_interval'])
        
        # UI setup
        self.init_ui()
        
        # Status
        self.is_running = False
    
    def init_ui(self):
        # Create central widget with tabs
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        
        # Control buttons
        control_layout = QHBoxLayout()
        
        self.start_button = QPushButton("开始监控")
        self.start_button.clicked.connect(self.start_monitoring)
        
        self.stop_button = QPushButton("停止监控")
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.stop_button.setEnabled(False)
        
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.stop_button)
        control_layout.addStretch()
        
        main_layout.addLayout(control_layout)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Create tabs
        self.dashboard_tab = DashboardTab(self.session_manager, self.protocol_analyzer)
        self.connections_tab = ConnectionsTab(self.session_manager)
        self.processes_tab = ProcessesTab(self.session_manager)
        self.protocols_tab = ProtocolsTab(self.protocol_analyzer)
        
        # Add tabs to tab widget
        self.tab_widget.addTab(self.dashboard_tab, "仪表盘")
        self.tab_widget.addTab(self.connections_tab, "连接列表")
        self.tab_widget.addTab(self.processes_tab, "进程流量")
        self.tab_widget.addTab(self.protocols_tab, "协议统计")
        
        main_layout.addWidget(self.tab_widget)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("监控已停止")
    
    def start_monitoring(self):
        # Check if Npcap is installed
        if not self.capture.check_npcap_installed():
            QMessageBox.critical(self, "错误", "Npcap未安装，请先安装Npcap")
            return
        
        # Start capture
        if not self.capture.start_capture():
            QMessageBox.critical(self, "错误", "无法启动抓包")
            return
        
        # Start packet processing thread
        self.packet_thread.start()
        
        # Update UI
        self.is_running = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status_bar.showMessage("监控运行中")
    
    def stop_monitoring(self):
        # Stop packet processing thread
        self.packet_thread.stop()
        self.packet_thread.wait()
        
        # Stop capture
        self.capture.stop_capture()
        
        # Update UI
        self.is_running = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_bar.showMessage("监控已停止")
    
    def update_ui(self):
        # Update all tabs
        self.dashboard_tab.update_stats()
        self.connections_tab.update_connections()
        self.processes_tab.update_processes()
        self.protocols_tab.update_protocols()
    
    def closeEvent(self, event):
        # Stop monitoring if running
        if self.is_running:
            self.stop_monitoring()
        event.accept()
