#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
后台管理服务器
提供HTML页面和API接口，用于账户管理和操作日志查看
"""

import http.server
import socketserver
import json
import sqlite3
import os
import socket
from urllib.parse import parse_qs, urlparse
from datetime import datetime

# 定义服务器端口
PORT = 8080

# 数据库文件路径 - 使用绝对路径
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'blacklist_vehicles.db')

# HTML文件保存目录
HTML_DIR = 'admin_html'

# 创建HTML目录（如果不存在）
os.makedirs(HTML_DIR, exist_ok=True)

# 初始化数据库表结构
def init_database():
    """初始化数据库表结构"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 检查users表是否有role字段，如果没有则添加
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'role' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
    
    # 确保admin用户的角色为admin
    cursor.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")
    
    # 检查是否有默认管理员用户，如果没有则创建
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if cursor.fetchone()[0] == 0:
        # 创建默认管理员用户，密码为admin，角色为admin
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("admin", "admin", "admin"))
    
    # 创建规则筛选表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS skip_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_type TEXT NOT NULL,
            rule_value TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 创建操作日志表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS operation_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            operation_type TEXT NOT NULL,
            operation_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# 初始化数据库
init_database()


class AdminHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """自定义HTTP请求处理器"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=HTML_DIR, **kwargs)
    
    def do_GET(self):
        """处理GET请求"""
        # 解析URL
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        
        # API请求处理
        if path.startswith('/api/'):
            self.handle_api_get(path)
        else:
            # 静态文件请求处理
            if path == '/':
                self.path = '/index.html'
            super().do_GET()
    
    def do_POST(self):
        """处理POST请求"""
        # 解析URL
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        
        # API请求处理
        if path.startswith('/api/'):
            self.handle_api_post(path)
        else:
            # 静态文件请求不支持POST
            self.send_error(405, "Method Not Allowed")
    
    def handle_api_get(self, path):
        """处理API GET请求"""
        # 解析URL查询参数
        from urllib.parse import parse_qs, urlparse
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        
        # 获取当前用户角色
        current_user_role = query_params.get('current_user_role', ['user'])[0]
        
        # 获取用户列表
        if path == '/api/users':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            # 检查是否是登录请求（没有current_user_role参数或者current_user_role为user）
            is_login_request = not query_params.get('current_user_role') or current_user_role == 'user'
            
            # 如果是登录请求，返回所有用户，否则根据当前用户角色过滤
            if is_login_request:
                users = self.get_users('creator')  # 使用creator角色获取所有用户
            else:
                users = self.get_users(current_user_role)
            
            self.wfile.write(json.dumps(users).encode('utf-8'))
        
        # 获取操作日志
        elif path == '/api/logs':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            logs = self.get_logs()
            self.wfile.write(json.dumps(logs).encode('utf-8'))
        
        # 获取可用角色选项
        elif path == '/api/roles':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            # 定义角色权限层级
            role_levels = {
                'user': 0,
                'admin': 1,
                'station_master': 2,
                'creator': 3
            }
            
            # 角色中文映射
            role_cn_map = {
                'user': '普通用户',
                'admin': '管理员',
                'station_master': '站长',
                'creator': '创世神'
            }
            
            # 获取当前用户角色
            current_user_role = query_params.get('current_user_role', ['user'])[0]
            current_level = role_levels.get(current_user_role, 0)
            
            # 根据当前用户角色获取可用角色选项
            available_roles = [
                {'value': role, 'label': role_cn_map[role]}
                for role, level in role_levels.items()
                if level < current_level
            ]
            
            self.wfile.write(json.dumps(available_roles).encode('utf-8'))
        
        # 获取规则筛选规则
        elif path == '/api/filter_rules':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            filter_rules = self.get_filter_rules()
            self.wfile.write(json.dumps(filter_rules).encode('utf-8'))
        
        else:
            self.send_error(404, "Not Found")
    
    def handle_api_post(self, path):
        """处理API POST请求"""
        # 读取请求体
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        # 解析JSON数据
        try:
            data = json.loads(post_data.decode('utf-8'))
        except json.JSONDecodeError:
            self.send_error(400, "Bad Request: Invalid JSON")
            return
        
        # 添加用户
        if path == '/api/users':
            username = data.get('username')
            password = data.get('password')
            role = data.get('role', 'user')
            current_user_role = data.get('current_user_role', 'user')  # 从前端获取当前用户角色
            
            # 验证角色值
            valid_roles = ['user', 'admin', 'station_master', 'creator']
            if role not in valid_roles:
                self.send_error(400, f"Bad Request: Invalid role. Valid roles are: {', '.join(valid_roles)}")
                return
            
            if not username or not password:
                self.send_error(400, "Bad Request: Missing username or password")
                return
            
            # 定义角色权限层级
            role_levels = {
                'user': 0,
                'admin': 1,
                'station_master': 2,
                'creator': 3
            }
            
            # 检查当前用户是否有权限添加该角色的用户
            current_level = role_levels.get(current_user_role, 0)
            target_level = role_levels.get(role, 0)
            
            if current_level <= target_level:
                self.send_error(403, "Forbidden: You don't have permission to add users with this role")
                return
            
            try:
                self.add_user(username, password, role)
                # 记录操作日志
                self.log_operation("admin", f"add_user_{username}")
                self.send_response(201)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"message": "User added successfully"}).encode('utf-8'))
            except sqlite3.IntegrityError:
                self.send_error(409, "Conflict: Username already exists")
            except Exception as e:
                self.send_error(500, f"Internal Server Error: {str(e)}")
        
        # 删除用户
        elif path == '/api/users/delete':
            user_id = data.get('id')
            current_user_role = data.get('current_user_role', 'user')  # 从前端获取当前用户角色
            
            if not user_id:
                self.send_error(400, "Bad Request: Missing user ID")
                return
            
            try:
                # 确保user_id是整数类型
                user_id = int(user_id)
                
                # 检查当前用户是否有权限删除该用户
                # 定义角色权限层级
                role_levels = {
                    'user': 0,
                    'admin': 1,
                    'station_master': 2,
                    'creator': 3
                }
                
                # 获取当前用户的角色层级
                current_level = role_levels.get(current_user_role, 0)
                
                # 获取目标用户的角色
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
                target_user = cursor.fetchone()
                conn.close()
                
                if not target_user:
                    self.send_error(404, "Not Found: User not found")
                    return
                
                # 获取目标用户的角色层级
                target_level = role_levels.get(target_user[0], 0)
                
                # 检查权限：只有角色层级高于目标用户的用户才能删除该用户
                if current_level <= target_level:
                    self.send_error(403, "Forbidden: You don't have permission to delete this user")
                    return
                
                # 执行删除操作
                self.delete_user(user_id)
                # 记录操作日志
                self.log_operation("admin", f"delete_user_{user_id}")
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"message": "User deleted successfully"}).encode('utf-8'))
            except ValueError as e:
                self.send_error(400, f"Bad Request: Invalid user ID format")
            except Exception as e:
                self.send_error(500, f"Internal Server Error: {str(e)}")
        
        # 添加规则筛选规则
        elif path == '/api/filter_rules':
            rule_type = data.get('rule_type')
            rule_value = data.get('rule_value')
            
            if not rule_type or not rule_value:
                self.send_error(400, "Bad Request: Missing rule_type or rule_value")
                return
            
            try:
                self.add_filter_rule(rule_type, rule_value)
                self.send_response(201)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"message": "Filter rule added successfully"}).encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Internal Server Error: {str(e)}")
        
        # 删除规则筛选规则
        elif path == '/api/filter_rules/delete':
            rule_id = data.get('id')
            
            if not rule_id:
                self.send_error(400, "Bad Request: Missing rule ID")
                return
            
            try:
                self.delete_filter_rule(rule_id)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"message": "Filter rule deleted successfully"}).encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Internal Server Error: {str(e)}")
        
        # 删除操作日志
        elif path == '/api/logs/delete':
            try:
                log_id = data.get('id')
                current_user_role = data.get('current_user_role')
                
                if not log_id:
                    self.send_error(400, "Bad Request: Missing log ID")
                    return
                
                # 确保log_id是整数类型
                log_id = int(log_id)
                
                # 只有创世神才能删除操作日志
                if current_user_role != 'creator':
                    self.send_error(403, "Forbidden: Only creators can delete operation logs")
                    return
                
                self.delete_log(log_id)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"message": "Log deleted successfully"}).encode('utf-8'))
            except ValueError as e:
                self.send_error(400, f"Bad Request: {str(e)}")
            except Exception as e:
                self.send_error(500, f"Internal Server Error: {str(e)}")
        
        else:
            self.send_error(404, "Not Found")
    
    def get_users(self, current_user_role='user'):
        """获取所有用户，根据当前用户角色过滤掉高权限用户"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 定义角色权限层级
        role_levels = {
            'user': 0,
            'admin': 1,
            'station_master': 2,
            'creator': 3
        }
        
        # 获取当前用户的角色层级
        current_level = role_levels.get(current_user_role, 0)
        
        # 查询所有用户
        cursor.execute("SELECT id, username, password, role, created_at FROM users")
        users = cursor.fetchall()
        
        conn.close()
        
        # 转换为字典列表，并根据角色层级过滤
        return [{
            "id": user[0],
            "username": user[1],
            "password": user[2],
            "role": user[3],
            "created_at": user[4]
        } for user in users if role_levels.get(user[3], 0) <= current_level]
    
    def add_user(self, username, password, role='user'):
        """添加用户"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, password, role)
        )
        
        conn.commit()
        conn.close()
    
    def delete_user(self, user_id):
        """删除用户"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        print(f"Attempting to delete user with id: {user_id}, type: {type(user_id)}")
        
        try:
            # 检查用户是否存在
            cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            print(f"User found: {user}")
            
            if not user:
                print(f"User with id {user_id} not found")
                conn.close()
                raise ValueError(f"User with id {user_id} not found")
            
            # 执行删除操作
            result = cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            print(f"Delete operation result: {result}")
            print(f"Rows affected: {cursor.rowcount}")
            
            # 检查是否有行被删除
            if cursor.rowcount == 0:
                print(f"Failed to delete user with id {user_id}, no rows affected")
                conn.close()
                raise ValueError(f"Failed to delete user with id {user_id}")
            
            conn.commit()
            print(f"Successfully deleted user with id {user_id}")
            conn.close()
        except Exception as e:
            print(f"Error deleting user: {str(e)}")
            conn.close()
            raise
    
    def get_filter_rules(self):
        """获取所有规则筛选规则，已分类"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, rule_type, rule_value, created_at FROM skip_rules")
        filter_rules = cursor.fetchall()
        
        conn.close()
        
        # 转换为字典列表
        rules_list = [{
            "id": rule[0],
            "rule_type": rule[1],
            "rule_value": rule[2],
            "created_at": rule[3]
        } for rule in filter_rules]
        
        # 按类型分类
        fixed_rules = [rule for rule in rules_list if rule['rule_type'] == 'fixed']
        regex_rules = [rule for rule in rules_list if rule['rule_type'] == 'regex']
        
        # 返回分类后的规则
        return {
            "fixed_rules": fixed_rules,
            "regex_rules": regex_rules
        }
    
    def add_filter_rule(self, rule_type, rule_value):
        """添加规则筛选规则"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO skip_rules (rule_type, rule_value) VALUES (?, ?)",
            (rule_type, rule_value)
        )
        
        conn.commit()
        conn.close()
    
    def delete_filter_rule(self, rule_id):
        """删除规则筛选规则"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM skip_rules WHERE id = ?", (rule_id,))
        
        conn.commit()
        conn.close()
    
    def get_logs(self):
        """获取操作日志"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, username, operation_type, operation_time FROM operation_logs ORDER BY operation_time DESC")
        logs = cursor.fetchall()
        
        conn.close()
        
        # 转换为字典列表
        return [{
            "id": log[0],
            "username": log[1],
            "operation_type": log[2],
            "operation_time": log[3]
        } for log in logs]
    
    def log_operation(self, username, operation_type):
        """记录操作日志"""
        # 查询当前用户的角色
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        # 不记录创世神的操作
        if user and user[0] == "creator":
            return
        
        # 记录其他所有用户的操作
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 使用本地时间记录操作日志
        local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO operation_logs (username, operation_type, operation_time) VALUES (?, ?, ?)",
            (username, operation_type, local_time)
        )
        
        conn.commit()
        conn.close()
    
    def delete_log(self, log_id):
        """删除操作日志"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        try:
            # 首先检查表结构
            cursor.execute("PRAGMA table_info(operation_logs)")
            table_info = cursor.fetchall()
            print(f"operation_logs表结构: {table_info}")
            
            # 查看日志表中的所有日志，用于调试
            cursor.execute("SELECT id FROM operation_logs")
            all_logs = cursor.fetchall()
            print(f"所有日志ID: {[log[0] for log in all_logs]}")
            
            # 执行删除操作
            print(f"尝试删除日志，ID: {log_id}，类型: {type(log_id)}")
            cursor.execute("DELETE FROM operation_logs WHERE id = ?", (log_id,))
            
            print(f"删除操作执行成功，影响行数: {cursor.rowcount}")
            
            # 提交事务
            conn.commit()
            print(f"删除日志提交成功，ID: {log_id}")
            conn.close()
        except Exception as e:
            print(f"删除日志失败，错误: {str(e)}")
            conn.close()
            raise


# 创建HTML文件
with open(os.path.join(HTML_DIR, 'index.html'), 'w', encoding='utf-8') as f:
    f.write('''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>后台管理 - 黑名单车辆筛选系统</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Microsoft YaHei', Arial, sans-serif;
            background-color: #f5f7fa;
            color: #606266;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background-color: #409eff;
            color: white;
            padding: 15px 0;
            margin-bottom: 30px;
            box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
        }
        
        header h1 {
            text-align: center;
            font-size: 24px;
        }
        
        nav {
            background-color: white;
            padding: 15px;
            margin-bottom: 30px;
            border-radius: 4px;
            box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
        }
        
        nav ul {
            list-style: none;
            display: flex;
            gap: 20px;
        }
        
        nav ul li a {
            text-decoration: none;
            color: #606266;
            padding: 8px 16px;
            border-radius: 4px;
            transition: all 0.3s;
        }
        
        nav ul li a:hover, nav ul li a.active {
            background-color: #ecf5ff;
            color: #409eff;
        }
        
        .content {
            background-color: white;
            padding: 20px;
            border-radius: 4px;
            box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
        }
        
        h2 {
            margin-bottom: 20px;
            color: #303133;
        }
        
        /* 登录样式 */
        .login-container {
            max-width: 400px;
            margin: 0 auto;
            padding: 40px;
            background-color: white;
            border-radius: 4px;
            box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
            margin-top: 50px;
        }
        
        .login-form {
            margin-top: 20px;
        }
        
        /* 用户管理样式 */
        .add-user-form {
            background-color: #f0f2f5;
            padding: 20px;
            border-radius: 4px;
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        
        .form-group input {
            width: 300px;
            padding: 8px 12px;
            border: 1px solid #dcdfe6;
            border-radius: 4px;
            font-size: 14px;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #409eff;
        }
        
        .btn {
            background-color: #409eff;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s;
        }
        
        .btn:hover {
            background-color: #66b1ff;
        }
        
        .btn-danger {
            background-color: #f56c6c;
        }
        
        .btn-danger:hover {
            background-color: #f78989;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ebeef5;
        }
        
        th {
            background-color: #f5f7fa;
            font-weight: bold;
            color: #303133;
        }
        
        tr:hover {
            background-color: #f5f7fa;
        }
        
        /* 日志样式 */
        .log-item {
            padding: 15px;
            border-bottom: 1px solid #ebeef5;
        }
        
        .log-item:last-child {
            border-bottom: none;
        }
        
        .log-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 5px;
        }
        
        .log-username {
            font-weight: bold;
            color: #409eff;
        }
        
        .log-time {
            color: #909399;
            font-size: 12px;
        }
        
        .log-type {
            color: #67c23a;
            font-size: 14px;
        }
    </style>
</head>
<body oncontextmenu="return false">
    <!-- 登录界面 -->
    <div id="login-container" class="login-container">
        <h2 style="text-align: center;">后台管理登录</h2>
        <form id="login-form" class="login-form">
            <div class="form-group">
                <label for="login-username">用户名:</label>
                <input type="text" id="login-username" name="username" required>
            </div>
            <div class="form-group">
                <label for="login-password">密码:</label>
                <input type="password" id="login-password" name="password" required>
            </div>
            <button type="submit" class="btn" style="width: 100%; margin-top: 20px;">登录</button>
            <div id="login-error" style="color: red; margin-top: 10px; text-align: center;"></div>
        </form>
    </div>
    
    <!-- 主界面 -->
    <div id="main-container" style="display: none;">
        <header style="display: flex; justify-content: space-between; align-items: center; padding: 0 20px;">
            <h1>黑名单车辆筛选系统 - 后台管理</h1>
            <div>
                <span id="current-user" style="margin-right: 20px;"></span>
                <button id="logout-btn" class="btn" style="padding: 6px 12px; font-size: 12px;">退出登录</button>
            </div>
        </header>
        
        <div class="container">
            <nav>
                <ul id="nav-menu">
                    <li><a href="#" class="active" onclick="showTab('users')">账户管理</a></li>
                    <li><a href="#" onclick="showTab('skip')">规则筛选</a></li>
                    <li><a href="#" onclick="showTab('logs')">操作日志</a></li>
                </ul>
            </nav>
            
            <div class="content">
                <!-- 账户管理 -->
                <div id="users-tab">
                    <h2>账户管理</h2>
                    
                    <div class="add-user-form" id="add-user-form-container">
                        <h3>添加新用户</h3>
                        <form id="add-user-form" autocomplete="off">
                            <div class="form-group">
                                <label for="username">用户名:</label>
                                <input type="text" id="username" name="username" required autocomplete="off">
                            </div>
                            <div class="form-group">
                                <label for="password">密码:</label>
                                <input type="password" id="password" name="password" required autocomplete="new-password">
                            </div>
                            <div class="form-group">
                                <label for="role">角色:</label>
                                <select id="role" name="role">
                                        <!-- 角色选项将通过JavaScript动态添加 -->
                                    </select>
                            </div>
                            <button type="submit" class="btn">添加用户</button>
                        </form>
                    </div>
                    
                    <h3>用户列表</h3>
                    <table id="users-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>用户名</th>
                                <th>角色</th>
                                <th>创建时间</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody id="users-tbody">
                            <!-- 用户数据将通过JavaScript动态加载 -->
                        </tbody>
                    </table>
                </div>
                
                <!-- 规则筛选 -->
                <div id="skip-tab" style="display: none;">
                    <h2>规则筛选</h2>
                    
                    <!-- 固定规则 -->
                    <div class="add-user-form" style="margin-bottom: 30px;">
                        <h3>固定规则</h3>
                        <form id="add-fixed-rule-form">
                            <div class="form-group">
                                <label for="fixed-rule">固定规则:</label>
                                <input type="text" id="fixed-rule" name="fixed_rule" required>
                            </div>
                            <button type="submit" class="btn">添加固定规则</button>
                        </form>
                        
                        <h4 style="margin-top: 20px;">固定规则列表</h4>
                        <div id="fixed-rules-list" style="margin-top: 10px;">
                            <!-- 固定规则列表将通过JavaScript动态加载 -->
                        </div>
                    </div>
                    
                    <!-- 正则表达式规则 -->
                    <div class="add-user-form">
                        <h3>正则表达式规则</h3>
                        <form id="add-regex-rule-form">
                            <div class="form-group">
                                <label for="regex-rule">正则表达式:</label>
                                <input type="text" id="regex-rule" name="regex_rule" required>
                            </div>
                            <button type="submit" class="btn">添加正则规则</button>
                        </form>
                        
                        <h4 style="margin-top: 20px;">正则规则列表</h4>
                        <div id="regex-rules-list" style="margin-top: 10px;">
                            <!-- 正则规则列表将通过JavaScript动态加载 -->
                        </div>
                    </div>
                </div>
                
                <!-- 操作日志 -->
                <div id="logs-tab" style="display: none;">
                    <h2>操作日志</h2>
                    <div id="logs-container">
                        <!-- 日志数据将通过JavaScript动态加载 -->
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // 全局变量，存储当前登录用户信息
        let currentUser = null;
        
        // 页面加载时直接显示登录界面
        window.addEventListener('DOMContentLoaded', function() {
            // 清除可能存在的会话存储
            sessionStorage.removeItem('currentUser');
            
            // 确保显示登录界面，隐藏主界面
            document.getElementById('main-container').style.display = 'none';
            document.getElementById('login-container').style.display = 'block';
        });
        
        // 禁用F12和Ctrl+U等快捷键
        document.addEventListener('keydown', function(e) {
            // 禁用F12
            if (e.key === 'F12') {
                e.preventDefault();
            }
            // 禁用Ctrl+U
            if (e.ctrlKey && e.key === 'u') {
                e.preventDefault();
            }
            // 禁用Ctrl+Shift+I
            if (e.ctrlKey && e.shiftKey && e.key === 'i') {
                e.preventDefault();
            }
            // 禁用Ctrl+Shift+J
            if (e.ctrlKey && e.shiftKey && e.key === 'j') {
                e.preventDefault();
            }
            // 禁用Ctrl+Shift+C
            if (e.ctrlKey && e.shiftKey && e.key === 'c') {
                e.preventDefault();
            }
        });
        
        // 加载用户列表
        function loadUsers() {
            fetch(`/api/users?current_user_role=${currentUser.role}`)
                .then(response => response.json())
                .then(users => {
                    const tbody = document.getElementById('users-tbody');
                    tbody.innerHTML = '';
                    
                    users.forEach(user => {
                        // 转换角色为中文显示
                        let roleText = '普通用户';
                        if (user.role === 'admin') {
                            roleText = '管理员';
                        } else if (user.role === 'station_master') {
                            roleText = '站长';
                        } else if (user.role === 'creator') {
                            roleText = '创世神';
                        }
                        
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${user.id}</td>
                            <td>${user.username}</td>
                            <td>${roleText}</td>
                            <td>${user.created_at}</td>
                            <td>
                                <button class="btn btn-danger" onclick="deleteUser(${user.id})">删除</button>
                            </td>
                        `;
                        tbody.appendChild(row);
                    });
                })
                .catch(error => console.error('加载用户失败:', error));
        }
        
        // 根据当前用户角色从后端获取并更新角色选择下拉框
        function loadRoleOptions() {
            fetch(`/api/roles?current_user_role=${currentUser.role}`)
                .then(response => response.json())
                .then(availableRoles => {
                    const roleSelect = document.getElementById('role');
                    // 清空现有选项
                    roleSelect.innerHTML = '';
                    
                    // 根据后端返回的可用角色添加选项
                    availableRoles.forEach(role => {
                        const option = document.createElement('option');
                        option.value = role.value;
                        option.textContent = role.label;
                        roleSelect.appendChild(option);
                    });
                })
                .catch(error => console.error('加载角色选项失败:', error));
        }
        
        // 添加用户
        document.getElementById('add-user-form').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const role = document.getElementById('role').value;
            
            fetch('/api/users', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password, role, current_user_role: currentUser.role })
            })
            .then(response => {
                if (response.ok) {
                    // 重置表单
                    this.reset();
                    // 重新加载用户列表
                    loadUsers();
                    alert('用户添加成功');
                } else if (response.status === 409) {
                    alert('用户名已存在');
                } else if (response.status === 403) {
                    alert('没有权限添加该角色的用户');
                } else {
                    throw new Error('添加用户失败');
                }
            })
            .catch(error => {
                console.error('添加用户失败:', error);
                alert('添加用户失败');
            });
        });
        
        // 删除用户
        function deleteUser(userId) {
            if (confirm('确定要删除这个用户吗？')) {
                fetch('/api/users/delete', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ id: userId, current_user_role: currentUser.role })
                })
                .then(response => {
                    if (response.ok) {
                        // 重新加载用户列表
                        loadUsers();
                        alert('用户删除成功');
                    } else if (response.status === 403) {
                        alert('没有权限删除该用户');
                    } else if (response.status === 404) {
                        alert('用户不存在');
                    } else {
                        throw new Error('删除用户失败');
                    }
                })
                .catch(error => {
                    console.error('删除用户失败:', error);
                    alert('删除用户失败，请稍后重试');
                });
            }
        }
        
        // 加载操作日志
        function loadLogs() {
            fetch('/api/logs')
                .then(response => response.json())
                .then(logs => {
                    const container = document.getElementById('logs-container');
                    container.innerHTML = '';
                    
                    if (logs.length === 0) {
                        container.innerHTML = '<p>暂无操作日志</p>';
                        return;
                    }
                    
                    logs.forEach(log => {
                        const logItem = document.createElement('div');
                        logItem.className = 'log-item';
                        logItem.innerHTML = `
                            <div class="log-header">
                                <span class="log-username">${log.username}</span>
                                <span class="log-time">${log.operation_time}</span>
                            </div>
                            <div class="log-type">${log.operation_type === 'login' ? '登录系统' : log.operation_type}</div>
                        `;
                        container.appendChild(logItem);
                    });
                })
                .catch(error => console.error('加载日志失败:', error));
        }
        
        // 登录功能
        document.getElementById('login-form').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const username = document.getElementById('login-username').value;
            const password = document.getElementById('login-password').value;
            const errorDiv = document.getElementById('login-error');
            
            // 验证用户登录
            fetch('/api/users')
                .then(response => response.json())
                .then(users => {
                    const user = users.find(u => u.username === username && u.password === password);
                    
                    if (user) {
                            // 登录成功
                            currentUser = user;
                            errorDiv.innerHTML = '';
                            
                            // 将用户信息保存到会话存储
                            sessionStorage.setItem('currentUser', JSON.stringify(currentUser));
                            
                            // 显示主界面
                            document.getElementById('login-container').style.display = 'none';
                            document.getElementById('main-container').style.display = 'block';
                            
                            // 显示当前用户名
                            let roleText = '普通用户';
                            if (user.role === 'admin') {
                                roleText = '管理员';
                            } else if (user.role === 'station_master') {
                                roleText = '站长';
                            } else if (user.role === 'creator') {
                                roleText = '创世神';
                            }
                            document.getElementById('current-user').innerHTML = `当前用户: ${user.username} (${roleText})`;
                            
                            // 根据用户角色决定显示内容
                            if (user.role === 'creator') {
                                // 只有创世神可以看到所有内容
                                document.getElementById('nav-menu').children[0].style.display = 'block'; // 显示账户管理标签
                                document.getElementById('nav-menu').children[1].style.display = 'block'; // 显示规则筛选标签
                                document.getElementById('add-user-form-container').style.display = 'block';
                                // 更新角色选择下拉框
                                loadRoleOptions();
                                // 加载用户列表
                                loadUsers();
                            } else if (user.role === 'admin' || user.role === 'station_master') {
                                // 管理员和站长可以看到账户管理，但不能看到规则筛选
                                document.getElementById('nav-menu').children[0].style.display = 'block'; // 显示账户管理标签
                                document.getElementById('nav-menu').children[1].style.display = 'none'; // 隐藏规则筛选标签
                                document.getElementById('add-user-form-container').style.display = 'block';
                                // 更新角色选择下拉框
                                loadRoleOptions();
                                // 加载用户列表
                                loadUsers();
                            } else {
                                // 普通用户只能看到操作日志
                                document.getElementById('nav-menu').children[0].style.display = 'none'; // 隐藏账户管理标签
                                document.getElementById('nav-menu').children[1].style.display = 'none'; // 隐藏规则筛选标签
                                document.getElementById('add-user-form-container').style.display = 'none';
                                // 切换到操作日志标签
                                showTab('logs');
                            }
                    } else {
                        // 登录失败
                        errorDiv.innerHTML = '用户名或密码错误';
                    }
                })
                .catch(error => {
                    console.error('登录失败:', error);
                    errorDiv.innerHTML = '登录失败，请稍后重试';
                });
        });
        
        // 修改showTab函数，确保不同角色的用户无法访问他们没有权限的标签页
        function showTab(tabName) {
            // 根据角色控制访问权限
            if (currentUser) {
                if (currentUser.role !== 'creator' && tabName === 'skip') {
                    // 只有创世神可以访问规则筛选页
                    tabName = 'users';
                } else if (currentUser.role !== 'admin' && currentUser.role !== 'creator' && currentUser.role !== 'station_master' && tabName === 'users') {
                    // 普通用户不能访问账户管理页
                    tabName = 'logs';
                }
            }
            
            // 隐藏所有标签页
            document.getElementById('users-tab').style.display = 'none';
            document.getElementById('skip-tab').style.display = 'none';
            document.getElementById('logs-tab').style.display = 'none';
            
            // 移除所有导航链接的active类
            document.querySelectorAll('nav ul li a').forEach(link => {
                link.classList.remove('active');
            });
            
            // 显示选中的标签页
            document.getElementById(tabName + '-tab').style.display = 'block';
            
            // 添加active类到对应的导航链接
            if (event) {
                event.target.classList.add('active');
            } else {
                // 如果没有event对象（比如从JavaScript调用），手动设置active类
                const navLinks = document.querySelectorAll('nav ul li a');
                navLinks.forEach(link => {
                    if (link.textContent.includes(tabName === 'users' ? '账户管理' : (tabName === 'skip' ? '规则筛选' : '操作日志'))) {
                        link.classList.add('active');
                    }
                });
            }
            
            // 加载数据
            if (tabName === 'users') {
                loadUsers();
            } else if (tabName === 'skip') {
                loadFilterRules();
            } else if (tabName === 'logs') {
                loadLogs();
            }
        }
        
        // 加载规则筛选规则
        function loadFilterRules() {
            // 使用API获取规则
            fetch('/api/filter_rules')
                .then(response => response.json())
                .then(data => {
                    const fixedRulesList = document.getElementById('fixed-rules-list');
                    const regexRulesList = document.getElementById('regex-rules-list');
                    
                    // 清空规则列表
                    fixedRulesList.innerHTML = '';
                    regexRulesList.innerHTML = '';
                    
                    // 显示固定规则（直接使用后端返回的分类数据）
                    const fixedRules = data.fixed_rules || [];
                    if (fixedRules.length === 0) {
                        fixedRulesList.innerHTML = '<p>暂无固定规则</p>';
                    } else {
                        fixedRules.forEach(rule => {
                            const ruleItem = document.createElement('div');
                            ruleItem.style.display = 'flex';
                            ruleItem.style.justifyContent = 'space-between';
                            ruleItem.style.alignItems = 'center';
                            ruleItem.style.padding = '10px';
                            ruleItem.style.borderBottom = '1px solid #ebeef5';
                            ruleItem.innerHTML = `
                                <span>${rule.rule_value}</span>
                                <button class="btn btn-danger" style="padding: 4px 8px; font-size: 12px;" onclick="deleteFilterRule(${rule.id})">删除</button>
                            `;
                            fixedRulesList.appendChild(ruleItem);
                        });
                    }
                    
                    // 显示正则规则（直接使用后端返回的分类数据）
                    const regexRules = data.regex_rules || [];
                    if (regexRules.length === 0) {
                        regexRulesList.innerHTML = '<p>暂无正则表达式规则</p>';
                    } else {
                        regexRules.forEach(rule => {
                            const ruleItem = document.createElement('div');
                            ruleItem.style.display = 'flex';
                            ruleItem.style.justifyContent = 'space-between';
                            ruleItem.style.alignItems = 'center';
                            ruleItem.style.padding = '10px';
                            ruleItem.style.borderBottom = '1px solid #ebeef5';
                            ruleItem.innerHTML = `
                                <span>${rule.rule_value}</span>
                                <button class="btn btn-danger" style="padding: 4px 8px; font-size: 12px;" onclick="deleteFilterRule(${rule.id})">删除</button>
                            `;
                            regexRulesList.appendChild(ruleItem);
                        });
                    }
                })
                .catch(error => {
                    console.error('加载规则失败:', error);
                    alert('加载规则失败，请稍后重试');
                });
        }
        
        // 添加固定规则
        document.getElementById('add-fixed-rule-form').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const fixedRule = document.getElementById('fixed-rule').value;
            
            // 使用API添加固定规则
            fetch('/api/filter_rules', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ rule_type: 'fixed', rule_value: fixedRule })
            })
            .then(response => response.json())
            .then(data => {
                alert('固定规则添加成功: ' + fixedRule);
                // 重置表单
                this.reset();
                // 重新加载规则筛选规则
                loadFilterRules();
            })
            .catch(error => {
                console.error('添加固定规则失败:', error);
                alert('添加固定规则失败，请稍后重试');
            });
        });
        
        // 添加正则表达式规则
        document.getElementById('add-regex-rule-form').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const regexRule = document.getElementById('regex-rule').value;
            
            // 使用API添加正则表达式规则
            fetch('/api/filter_rules', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ rule_type: 'regex', rule_value: regexRule })
            })
            .then(response => response.json())
            .then(data => {
                alert('正则表达式规则添加成功: ' + regexRule);
                // 重置表单
                this.reset();
                // 重新加载规则筛选规则
                loadFilterRules();
            })
            .catch(error => {
                console.error('添加正则表达式规则失败:', error);
                alert('添加正则表达式规则失败，请稍后重试');
            });
        });
        
        // 删除规则
        function deleteFilterRule(ruleId) {
            if (confirm('确定要删除这个规则吗？')) {
                fetch('/api/filter_rules/delete', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ id: ruleId })
                })
                .then(response => response.json())
                .then(data => {
                    alert('规则删除成功');
                    // 重新加载规则筛选规则
                    loadFilterRules();
                })
                .catch(error => {
                    console.error('删除规则失败:', error);
                    alert('删除规则失败，请稍后重试');
                });
            }
        }
        
        // 退出登录功能
        document.getElementById('logout-btn').addEventListener('click', function() {
            // 清除当前用户信息
            currentUser = null;
            
            // 清除会话存储中的用户信息
            sessionStorage.removeItem('currentUser');
            
            // 显示登录界面，隐藏主界面
            document.getElementById('main-container').style.display = 'none';
            document.getElementById('login-container').style.display = 'block';
            
            // 清空登录表单
            document.getElementById('login-form').reset();
            document.getElementById('login-error').innerHTML = '';
        });
    </script>
</body>
</html>
''')


# 启动服务器
if __name__ == "__main__":
    # 绑定到所有网卡，允许外部访问
    with socketserver.TCPServer(("0.0.0.0", PORT), AdminHTTPRequestHandler) as httpd:
        print(f"后台管理服务器已启动，本地访问地址: http://localhost:{PORT}")
        print(f"外部访问地址: http://{socket.gethostbyname(socket.gethostname())}:{PORT}")
        print("按 Ctrl+C 停止服务器")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n服务器已停止")
            }