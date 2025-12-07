#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GeoLite2数据库查询模块
使用MaxMind GeoLite2数据库获取IP地址的地理位置信息
"""

import geoip2.database
import os
import socket

class GeoLite2Locator:
    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), '..', 'GeoLite2-City.mmdb')
            db_path = os.path.abspath(db_path)
        
        self.db_path = db_path
        self.reader = None
        
        # 初始化数据库连接
        self._init_database()
        
    def _init_database(self):
        """初始化GeoLite2数据库连接"""
        try:
            if os.path.exists(self.db_path):
                self.reader = geoip2.database.Reader(self.db_path)
                print(f"GeoLite2数据库已加载: {self.db_path}")
            else:
                print(f"GeoLite2数据库文件不存在: {self.db_path}")
                self.reader = None
        except Exception as e:
            print(f"GeoLite2数据库初始化失败: {e}")
            self.reader = None
            
    def get_location(self, ip):
        """获取IP地址的地理位置信息"""
        if not ip or ip in ['127.0.0.1', 'localhost', 'N/A', '::1']:
            return {
                'country': '本地',
                'region': '本地',
                'city': '北京',
                'lat': 39.9042,
                'lon': 116.4074
            }
            
        # 检查是否为私有IP地址范围
        if self._is_private_ip(ip):
            return {
                'country': '本地网络',
                'region': '局域网',
                'city': '北京',
                'lat': 39.9042,
                'lon': 116.4074
            }
            
        # 使用GeoLite2数据库查询
        if self.reader:
            try:
                response = self.reader.city(ip)
                return {
                    'country': response.country.names.get('zh-CN', response.country.name) if response.country.name else '未知',
                    'region': response.subdivisions.most_specific.names.get('zh-CN', response.subdivisions.most_specific.name) if response.subdivisions.most_specific.name else '未知',
                    'city': response.city.names.get('zh-CN', response.city.name) if response.city.name else '未知',
                    'lat': float(response.location.latitude) if response.location.latitude else None,
                    'lon': float(response.location.longitude) if response.location.longitude else None
                }
            except Exception as e:
                print(f"GeoLite2查询失败 ({ip}): {e}")
        
        # 默认返回值
        return {
            'country': '未知',
            'region': '未知',
            'city': '未知',
            'lat': None,
            'lon': None
        }
        
    def _is_private_ip(self, ip):
        """检查是否为私有IP地址"""
        try:
            ip_obj = socket.ip_address(ip)
            return ip_obj.is_private
        except:
            # 对于IPv4格式的简单检查
            if ip.startswith(('192.168.', '10.', '172.')):
                if ip.startswith('172.'):
                    parts = ip.split('.')
                    if len(parts) == 4 and 16 <= int(parts[1]) <= 31:
                        return True
                else:
                    return True
            return False
            
    def close(self):
        """关闭数据库连接"""
        if self.reader:
            self.reader.close()

# 创建全局实例
geolite2_locator = GeoLite2Locator()

if __name__ == "__main__":
    # 测试代码
    locator = GeoLite2Locator()
    test_ips = ['8.8.8.8', '1.1.1.1', '192.168.1.1', '127.0.0.1']
    
    for ip in test_ips:
        location = locator.get_location(ip)
        print(f"{ip}: {location}")