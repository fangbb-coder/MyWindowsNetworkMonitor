#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP地理位置查询模块
使用本地数据库和在线API获取IP地址的地理位置信息
"""

import json
import sqlite3
import os
import requests
import time
from datetime import datetime, timedelta

# 导入GeoLite2查询模块
try:
    from .geolite2 import geolite2_locator
    HAS_GEOLITE2 = True
except ImportError:
    HAS_GEOLITE2 = False
    print("警告: 无法导入GeoLite2查询模块")

class IPGeolocation:
    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), 'ip_geolocation.db')
        self.db_path = db_path
        self.cache = {}
        self.cache_ttl = timedelta(hours=24)  # 缓存24小时
        
        # 初始化数据库
        self._init_database()
        
        # 预置的常用IP地址库
        self.predefined_ips = self._create_predefined_ip_database()
        
        # 在线查询API配置
        self.api_endpoints = [
            "http://ip-api.com/json/{}",  # 免费API，限制每分钟45次
            # 可以添加更多备用API
        ]
        self.current_api_index = 0
        
    def _init_database(self):
        """初始化SQLite数据库"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_cache (
                ip TEXT PRIMARY KEY,
                country TEXT,
                region TEXT,
                city TEXT,
                isp TEXT,
                lat REAL,
                lon REAL,
                query_time TEXT,
                last_updated TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def get_location(self, ip, force_online=False):
        """获取IP地址的地理位置信息
        Args:
            ip (str): IP地址
            force_online (bool): 是否强制使用在线查询，即使有缓存也忽略
        """
        if not ip or ip in ['127.0.0.1', 'localhost', 'N/A']:
            return {
                'country': '本地',
                'region': '本地',
                'city': '北京',
                'isp': '本地网络',
                'lat': 39.9042,
                'lon': 116.4074
            }
            
        # 检查是否为私有IP地址范围
        if self._is_private_ip(ip):
            return {
                'country': '本地网络',
                'region': '局域网',
                'city': '私有网络',
                'isp': '内部网络',
                'lat': None,
                'lon': None
            }
            
        # 检查内存缓存（除非强制在线查询）
        if not force_online and ip in self.cache:
            cache_entry = self.cache[ip]
            if datetime.now() - cache_entry['timestamp'] < self.cache_ttl:
                return cache_entry['data']
        
        # 使用GeoLite2数据库查询（除非强制在线查询）
        if HAS_GEOLITE2 and not force_online:
            geolite_data = geolite2_locator.get_location(ip)
            if geolite_data:
                result = {
                    'country': geolite_data['country'],
                    'region': geolite_data['region'],
                    'city': geolite_data['city'],
                    'isp': geolite_data.get('isp', '未知'),
                    'lat': geolite_data['lat'],
                    'lon': geolite_data['lon']
                }
                # 保存到数据库和内存缓存
                self._save_to_database(ip, result)
                self.cache[ip] = {
                    'data': result,
                    'timestamp': datetime.now()
                }
                return result
        
        # 1. 首先检查预置IP库（离线）- 除非强制在线查询
        if not force_online:
            predefined_result = self._get_from_predefined(ip)
            if predefined_result:
                # 保存到数据库和内存缓存
                self._save_to_database(ip, predefined_result)
                self.cache[ip] = {
                    'data': predefined_result,
                    'timestamp': datetime.now()
                }
                return predefined_result
        
        # 2. 检查数据库缓存（离线）- 除非强制在线查询
        if not force_online:
            db_result = self._get_from_database(ip)
            if db_result:
                # 更新内存缓存
                self.cache[ip] = {
                    'data': db_result,
                    'timestamp': datetime.now()
                }
                return db_result
            
        # 3. 从在线API查询（备用方案或强制查询）
        try:
            online_result = self._query_online(ip)
            if online_result:
                # 保存到数据库和内存缓存
                self._save_to_database(ip, online_result)
                self.cache[ip] = {
                    'data': online_result,
                    'timestamp': datetime.now()
                }
                return online_result
        except Exception as e:
            print(f"在线查询失败: {e}")
            
        # 如果强制在线查询但失败了，仍然尝试使用缓存
        if force_online:
            db_result = self._get_from_database(ip)
            if db_result:
                # 更新内存缓存
                self.cache[ip] = {
                    'data': db_result,
                    'timestamp': datetime.now()
                }
                return db_result
            
        # 如果所有方法都失败，返回默认值
        return {
            'country': '未知',
            'region': '未知',
            'city': '未知',
            'isp': '未知',
            'lat': None,
            'lon': None
        }
        
    def _get_from_database(self, ip):
        """从数据库获取缓存的地理位置信息"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT country, region, city, isp, lat, lon, last_updated 
                FROM ip_cache 
                WHERE ip = ?
            ''', (ip,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                # 检查缓存是否过期
                last_updated = datetime.fromisoformat(result[6])
                if datetime.now() - last_updated < self.cache_ttl:
                    return {
                        'country': result[0],
                        'region': result[1],
                        'city': result[2],
                        'isp': result[3],
                        'lat': result[4],
                        'lon': result[5]
                    }
        except Exception as e:
            print(f"数据库查询错误: {e}")
            
        return None
        
    def _save_to_database(self, ip, location_data):
        """保存地理位置信息到数据库"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO ip_cache 
                (ip, country, region, city, isp, lat, lon, query_time, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ip,
                location_data.get('country', '未知'),
                location_data.get('region', '未知'),
                location_data.get('city', '未知'),
                location_data.get('isp', '未知'),
                location_data.get('lat'),
                location_data.get('lon'),
                datetime.now().isoformat(),
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"数据库保存错误: {e}")
            
    def _query_online(self, ip):
        """从在线API查询地理位置信息"""
        try:
            # 使用ip-api.com免费API
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,lat,lon,query"
            
            # 设置超时时间
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', '未知'),
                        'region': data.get('regionName', '未知'),
                        'city': data.get('city', '未知'),
                        'isp': data.get('isp', '未知'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon')
                    }
                else:
                    print(f"API查询失败: {data.get('message', '未知错误')}")
            else:
                print(f"HTTP错误: {response.status_code}")
                
        except requests.exceptions.Timeout:
            print(f"在线查询超时: {ip}")
        except requests.exceptions.RequestException as e:
            print(f"网络请求错误: {e}")
        except Exception as e:
            print(f"在线查询异常: {e}")
            
        return None
        
    def batch_get_locations(self, ip_list):
        """批量获取地理位置信息"""
        results = {}
        for ip in ip_list:
            results[ip] = self.get_location(ip)
        return results
        
    def get_location_summary(self, ip):
        """获取简化的地理位置摘要"""
        location = self.get_location(ip)
        if location['country'] == '本地' or location['country'] == '未知':
            return location['country']
        
        parts = []
        if location['city'] and location['city'] != '未知':
            parts.append(location['city'])
        if location['region'] and location['region'] != '未知':
            parts.append(location['region'])
        if location['country'] and location['country'] != '未知':
            parts.append(location['country'])
            
        return ' · '.join(parts) if parts else location['country']
    
    def format_location(self, location_info):
        """格式化地理位置信息为可读字符串（中文显示）"""
        if not location_info:
            return '未知'
        
        # 检查是否为私有IP
        if location_info.get('country') == '本地' or location_info.get('country') == '本地网络':
            return '本地网络'
        
        if location_info.get('country') == '未知':
            return '未知'
        
        # 将英文国家/地区名称转换为中文
        country = self._translate_country(location_info.get('country', '未知'))
        region = self._translate_region(location_info.get('region', '未知'))
        city = location_info.get('city', '未知')
        
        # 如果城市和地区相同，只显示一个
        if city == region:
            region = ''
        
        parts = []
        if city and city != '未知':
            parts.append(city)
        if region and region != '未知':
            parts.append(region)
        if country and country != '未知':
            parts.append(country)
            
        return ' · '.join(parts) if parts else country
    
    def _translate_country(self, country_name):
        """将国家名称翻译为中文"""
        country_mapping = {
            'United States': '美国',
            'China': '中国',
            'Japan': '日本',
            'South Korea': '韩国',
            'Germany': '德国',
            'United Kingdom': '英国',
            'France': '法国',
            'Canada': '加拿大',
            'Australia': '澳大利亚',
            'Russia': '俄罗斯',
            'Brazil': '巴西',
            'India': '印度',
            'Singapore': '新加坡',
            'Hong Kong': '香港',
            'Taiwan': '台湾',
            'Macao': '澳门'
        }
        return country_mapping.get(country_name, country_name)
    
    def _translate_region(self, region_name):
        """将地区名称翻译为中文"""
        region_mapping = {
            'California': '加利福尼亚',
            'New York': '纽约',
            'Texas': '德克萨斯',
            'Florida': '佛罗里达',
            'Illinois': '伊利诺伊',
            'Washington': '华盛顿',
            'Beijing': '北京',
            'Shanghai': '上海',
            'Guangdong': '广东',
            'Zhejiang': '浙江',
            'Jiangsu': '江苏',
            'Tokyo': '东京',
            'Osaka': '大阪',
            'Seoul': '首尔',
            'Berlin': '柏林',
            'London': '伦敦',
            'Paris': '巴黎'
        }
        return region_mapping.get(region_name, region_name)
        
    def _is_private_ip(self, ip):
        """检查是否为私有IP地址"""
        try:
            # 解析IP地址
            ip_parts = list(map(int, ip.split('.')))
            
            # 检查私有IP地址范围
            # 10.0.0.0 - 10.255.255.255
            if ip_parts[0] == 10:
                return True
            
            # 172.16.0.0 - 172.31.255.255
            if ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31:
                return True
            
            # 192.168.0.0 - 192.168.255.255
            if ip_parts[0] == 192 and ip_parts[1] == 168:
                return True
            
            # 169.254.0.0 - 169.254.255.255 (链路本地)
            if ip_parts[0] == 169 and ip_parts[1] == 254:
                return True
                
        except (ValueError, IndexError):
            # 如果IP格式不正确，视为非私有IP
            pass
            
        return False

    def _create_predefined_ip_database(self):
        """创建预置的常用IP地址库"""
        predefined_ips = {
            # 常用DNS服务器
            '8.8.8.8': {'country': '美国', 'region': '加利福尼亚', 'city': '山景城', 'isp': 'Google', 'lat': 37.4056, 'lon': -122.0775},
            '8.8.4.4': {'country': '美国', 'region': '加利福尼亚', 'city': '山景城', 'isp': 'Google', 'lat': 37.4056, 'lon': -122.0775},
            '1.1.1.1': {'country': '美国', 'region': '加利福尼亚', 'city': '洛杉矶', 'isp': 'CloudFlare', 'lat': 34.0522, 'lon': -118.2437},
            '1.0.0.1': {'country': '美国', 'region': '加利福尼亚', 'city': '洛杉矶', 'isp': 'CloudFlare', 'lat': 34.0522, 'lon': -118.2437},
            '9.9.9.9': {'country': '美国', 'region': '弗吉尼亚', 'city': '阿什本', 'isp': 'Quad9', 'lat': 39.0437, 'lon': -77.4875},
            '208.67.222.222': {'country': '美国', 'region': '加利福尼亚', 'city': '圣何塞', 'isp': 'OpenDNS', 'lat': 37.3382, 'lon': -121.8863},
            '208.67.220.220': {'country': '美国', 'region': '加利福尼亚', 'city': '圣何塞', 'isp': 'OpenDNS', 'lat': 37.3382, 'lon': -121.8863},
            
            # 常用云服务IP
            '52.216.0.0': {'country': '美国', 'region': '弗吉尼亚', 'city': '阿什本', 'isp': 'Amazon AWS', 'lat': 39.0437, 'lon': -77.4875},
            '54.240.0.0': {'country': '美国', 'region': '弗吉尼亚', 'city': '阿什本', 'isp': 'Amazon AWS', 'lat': 39.0437, 'lon': -77.4875},
            '104.16.0.0': {'country': '美国', 'region': '加利福尼亚', 'city': '旧金山', 'isp': 'CloudFlare', 'lat': 37.7749, 'lon': -122.4194},
            '172.217.0.0': {'country': '美国', 'region': '加利福尼亚', 'city': '山景城', 'isp': 'Google', 'lat': 37.4056, 'lon': -122.0775},
            
            # 常用网站IP
            '151.101.0.0': {'country': '美国', 'region': '加利福尼亚', 'city': '旧金山', 'isp': 'Fastly', 'lat': 37.7749, 'lon': -122.4194},
            '199.232.0.0': {'country': '美国', 'region': '加利福尼亚', 'city': '旧金山', 'isp': 'Fastly', 'lat': 37.7749, 'lon': -122.4194},
            '185.199.0.0': {'country': '美国', 'region': '加利福尼亚', 'city': '旧金山', 'isp': 'GitHub', 'lat': 37.7749, 'lon': -122.4194},
            
            # 中国常用IP
            '114.114.114.114': {'country': '中国', 'region': '江苏', 'city': '南京', 'isp': '114DNS', 'lat': 32.0603, 'lon': 118.7969},
            '119.29.29.29': {'country': '中国', 'region': '广东', 'city': '深圳', 'isp': 'DNSPod', 'lat': 22.5431, 'lon': 114.0579},
            '180.76.76.76': {'country': '中国', 'region': '北京', 'city': '北京', 'isp': '百度', 'lat': 39.9042, 'lon': 116.4074},
            
            # 其他常用服务
            '13.107.21.200': {'country': '美国', 'region': '华盛顿', 'city': '雷德蒙德', 'isp': 'Microsoft', 'lat': 47.6740, 'lon': -122.1215},
            '20.190.160.0': {'country': '美国', 'region': '华盛顿', 'city': '雷德蒙德', 'isp': 'Microsoft', 'lat': 47.6740, 'lon': -122.1215},
            '52.114.128.0': {'country': '美国', 'region': '华盛顿', 'city': '雷德蒙德', 'isp': 'Microsoft', 'lat': 47.6740, 'lon': -122.1215},
        }
        
        # 将预置IP数据保存到数据库
        for ip, location_data in predefined_ips.items():
            self._save_predefined_to_database(ip, location_data)
        
        return predefined_ips
    
    def _save_predefined_to_database(self, ip, location_data):
        """保存预置IP数据到数据库"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 检查是否已存在
            cursor.execute('SELECT ip FROM ip_cache WHERE ip = ?', (ip,))
            if not cursor.fetchone():
                cursor.execute('''
                    INSERT INTO ip_cache 
                    (ip, country, region, city, isp, lat, lon, query_time, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ip,
                    location_data.get('country', '未知'),
                    location_data.get('region', '未知'),
                    location_data.get('city', '未知'),
                    location_data.get('isp', '未知'),
                    location_data.get('lat'),
                    location_data.get('lon'),
                    datetime.now().isoformat(),
                    datetime.now().isoformat()
                ))
                
                conn.commit()
            conn.close()
        except Exception as e:
            print(f"预置IP数据库保存错误: {e}")
    
    def _get_from_predefined(self, ip):
        """从预置IP库中获取地理位置信息"""
        return self.predefined_ips.get(ip)

    def _create_predefined_ip_database(self):
        """创建预置的常用IP地址库"""
        predefined_ips = {
            # 常用DNS服务器
            '8.8.8.8': {'country': '美国', 'region': '加利福尼亚', 'city': '山景城', 'isp': 'Google', 'lat': 37.4056, 'lon': -122.0775},
            '8.8.4.4': {'country': '美国', 'region': '加利福尼亚', 'city': '山景城', 'isp': 'Google', 'lat': 37.4056, 'lon': -122.0775},
            '1.1.1.1': {'country': '美国', 'region': '加利福尼亚', 'city': '洛杉矶', 'isp': 'CloudFlare', 'lat': 34.0522, 'lon': -118.2437},
            '1.0.0.1': {'country': '美国', 'region': '加利福尼亚', 'city': '洛杉矶', 'isp': 'CloudFlare', 'lat': 34.0522, 'lon': -118.2437},
            '9.9.9.9': {'country': '美国', 'region': '弗吉尼亚', 'city': '阿什本', 'isp': 'Quad9', 'lat': 39.0437, 'lon': -77.4875},
            '208.67.222.222': {'country': '美国', 'region': '加利福尼亚', 'city': '圣何塞', 'isp': 'OpenDNS', 'lat': 37.3382, 'lon': -121.8863},
            '208.67.220.220': {'country': '美国', 'region': '加利福尼亚', 'city': '圣何塞', 'isp': 'OpenDNS', 'lat': 37.3382, 'lon': -121.8863},
            
            # 常用云服务IP
            '52.216.0.0': {'country': '美国', 'region': '弗吉尼亚', 'city': '阿什本', 'isp': 'Amazon AWS', 'lat': 39.0437, 'lon': -77.4875},
            '54.240.0.0': {'country': '美国', 'region': '弗吉尼亚', 'city': '阿什本', 'isp': 'Amazon AWS', 'lat': 39.0437, 'lon': -77.4875},
            '104.16.0.0': {'country': '美国', 'region': '加利福尼亚', 'city': '旧金山', 'isp': 'CloudFlare', 'lat': 37.7749, 'lon': -122.4194},
            '172.217.0.0': {'country': '美国', 'region': '加利福尼亚', 'city': '山景城', 'isp': 'Google', 'lat': 37.4056, 'lon': -122.0775},
            
            # 常用网站IP
            '151.101.0.0': {'country': '美国', 'region': '加利福尼亚', 'city': '旧金山', 'isp': 'Fastly', 'lat': 37.7749, 'lon': -122.4194},
            '199.232.0.0': {'country': '美国', 'region': '加利福尼亚', 'city': '旧金山', 'isp': 'Fastly', 'lat': 37.7749, 'lon': -122.4194},
            '185.199.0.0': {'country': '美国', 'region': '加利福尼亚', 'city': '旧金山', 'isp': 'GitHub', 'lat': 37.7749, 'lon': -122.4194},
            
            # 中国常用IP
            '114.114.114.114': {'country': '中国', 'region': '江苏', 'city': '南京', 'isp': '114DNS', 'lat': 32.0603, 'lon': 118.7969},
            '119.29.29.29': {'country': '中国', 'region': '广东', 'city': '深圳', 'isp': 'DNSPod', 'lat': 22.5431, 'lon': 114.0579},
            '180.76.76.76': {'country': '中国', 'region': '北京', 'city': '北京', 'isp': '百度', 'lat': 39.9042, 'lon': 116.4074},
            
            # 其他常用服务
            '13.107.21.200': {'country': '美国', 'region': '华盛顿', 'city': '雷德蒙德', 'isp': 'Microsoft', 'lat': 47.6740, 'lon': -122.1215},
            '20.190.160.0': {'country': '美国', 'region': '华盛顿', 'city': '雷德蒙德', 'isp': 'Microsoft', 'lat': 47.6740, 'lon': -122.1215},
            '52.114.128.0': {'country': '美国', 'region': '华盛顿', 'city': '雷德蒙德', 'isp': 'Microsoft', 'lat': 47.6740, 'lon': -122.1215},
        }
        
        # 将预置IP数据保存到数据库
        for ip, location_data in predefined_ips.items():
            self._save_predefined_to_database(ip, location_data)
        
        return predefined_ips
    
    def _save_predefined_to_database(self, ip, location_data):
        """保存预置IP数据到数据库"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 检查是否已存在
            cursor.execute('SELECT ip FROM ip_cache WHERE ip = ?', (ip,))
            if not cursor.fetchone():
                cursor.execute('''
                    INSERT INTO ip_cache 
                    (ip, country, region, city, isp, lat, lon, query_time, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ip,
                    location_data.get('country', '未知'),
                    location_data.get('region', '未知'),
                    location_data.get('city', '未知'),
                    location_data.get('isp', '未知'),
                    location_data.get('lat'),
                    location_data.get('lon'),
                    datetime.now().isoformat(),
                    datetime.now().isoformat()
                ))
                
                conn.commit()
            conn.close()
        except Exception as e:
            print(f"预置IP数据库保存错误: {e}")
    
    def _get_from_predefined(self, ip):
        """从预置IP库中获取地理位置信息"""
        return self.predefined_ips.get(ip)

# 创建全局实例
ip_geolocator = IPGeolocation()