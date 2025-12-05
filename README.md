# DockPorts - 容器端口监控工具

一个现代化的Docker容器端口监控和可视化工具，帮助您轻松管理和监控NAS或服务器上的端口使用情况。

## ✨ 功能特性

- **Docker集成**: 通过Docker API实时监控容器端口映射
- **系统监控**: 使用netstat监控主机端口使用情况
- **可视化展示**: 美观的卡片式界面，类似Docker Compose Maker风格
- **实时刷新**: 支持手动和自动刷新端口信息
- **响应式设计**: 支持桌面和移动设备
- **智能排序**: 端口按顺序排列，空隙用灰色卡片标注
- **来源标识**: 区分Docker容器端口和系统服务端口
- **端口隐藏**: 支持隐藏不需要显示的端口，提供"已隐藏"标签页查看
- **批量操作**: 支持批量隐藏/取消隐藏端口范围
- **虚拟端口**: 隐藏端口以虚线边框样式区分显示
- **实时同步**: 隐藏/取消隐藏操作后立即更新显示状态
- **账号登陆**：保护端口隐私安全

## 🖼️ 界面预览

界面采用现代化设计，包含：
- 蓝色渐变背景
- 卡片式端口展示
- 实时统计信息
- 响应式布局

## ⭐ 推荐用法

### Docker-Compose

```
version: '3.8'

services:
  dockports:
    image: ghcr.io/yusuaois/dockportsrb:latest
    container_name: dockportsrb
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./config:/app/config
    environment:
      - DOCKPORTS_PORT=7577
      - SECRET_KEY=default       # 自定义Bcrypt加密密钥
      - ADMIN_USERNAME=admin     # 自己的管理员帐号
      - ADMIN_PASSWORD=admin123  # 自己的管理员密码
      - TZ=Asia/Shanghai
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:7577/api/auth/check"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
```
