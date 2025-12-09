# 黑名单车辆筛选系统

一个用于筛选黑名单车辆的系统，包含主程序和后台管理功能。

## 功能特性

- 黑名单车辆筛选
- 统计分析
- 黑名单数据库管理
- 后台管理系统
- 支持内网穿透

## 项目结构

- `Compares_Excel_PySide6.py` - 主程序
- `admin_server.py` - 后台管理服务器
- `admin_html/` - 后台管理页面
- `app_icon.ico` - 应用图标
- `license.txt` - 许可证文件

## 使用说明

1. 启动后台管理服务器：
   ```bash
   python admin_server.py
   ```

2. 运行主程序：
   ```bash
   python Compares_Excel_PySide6.py
   ```

3. 访问后台管理页面：
   - 本地：http://localhost:8080
   - 外部：http://[你的IP地址]:8080

## 内网穿透

支持使用内网穿透工具（如ngrok）将服务暴露到公网：

```bash
ngrok http 8080
```

## 安装包生成

使用Inno Setup编译`installer.iss`文件生成安装包。