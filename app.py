#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DockPorts - Containerized NAS Port Recording Tool (with Login System)

Main features:
1. User Authentication System
2. Monitor container port mappings via Docker API
3. Monitor host port usage via netstat
4. Visual representation of port usage status
"""

import docker
import subprocess
import json
import re
from flask import Flask, render_template, jsonify, request, session
import logging
from datetime import datetime
import os
import time
import bcrypt
import argparse
import threading
import shutil
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Load secret key from environment or use a default for development
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")

# Configuration file paths
CONFIG_DIR = os.path.expanduser("/app/config")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
HIDDEN_PORTS_FILE = os.path.join(CONFIG_DIR, "hidden_ports.json")
USERS_FILE = os.path.join(CONFIG_DIR, "users.json")

# File write lock to prevent corruption during concurrent JSON writes
file_lock = threading.Lock()


def init_config():
    """Initialize configuration files."""
    os.makedirs(CONFIG_DIR, exist_ok=True)

    # Initialize main config file
    if not os.path.exists(CONFIG_FILE):
        example_config_file = os.path.join(
            os.path.dirname(__file__), "config.json.example"
        )

        if os.path.exists(example_config_file):
            shutil.copy2(example_config_file, CONFIG_FILE)
            print(f"Config file copied from example: {CONFIG_FILE}")
        else:
            # Default configuration if example is not found
            default_config = {
                "SSH:host": "22:tcp",
                "HTTP:host": "80:tcp",
                "HTTPS:host": "443:tcp",
                "MySQL:host": "3306:tcp",
                "PostgreSQL:host": "5432:tcp",
                "Redis:host": "6379:tcp",
                "MongoDB:host": "27017:tcp",
                "Elasticsearch:host": "9200:tcp",
                "DockPorts:docker": "7575:tcp",
            }
            with file_lock:
                with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                    json.dump(default_config, f, indent=2, ensure_ascii=False)
            print(f"Config file created (default config): {CONFIG_FILE}")

    # Initialize hidden ports config file
    if not os.path.exists(HIDDEN_PORTS_FILE):
        with file_lock:
            with open(HIDDEN_PORTS_FILE, "w", encoding="utf-8") as f:
                json.dump([], f, indent=2, ensure_ascii=False)
        print(f"Hidden ports config file created: {HIDDEN_PORTS_FILE}")


def load_config():
    """Load configuration file, supporting the format: service_name:docker/host -> port:tcp/udp"""
    try:
        if not os.path.exists(CONFIG_FILE):
            return {}
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            raw_config = json.load(f)

        processed_config = {}
        for key, value in raw_config.items():
            if isinstance(value, str) and ":" in value:
                # New format: 'Service:type': 'Port:protocol'
                if ":" in key and (key.endswith(":docker") or key.endswith(":host")):
                    service_name = key.rsplit(":", 1)[0]
                    service_type = key.rsplit(":", 1)[1]
                    value_parts = value.split(":")
                    if len(value_parts) >= 2:
                        try:
                            port = int(value_parts[0])
                            protocol = value_parts[1].upper()
                            processed_config[service_name] = {
                                "port": port,
                                "protocol": protocol,
                                "service_type": service_type,
                            }
                        except ValueError:
                            processed_config[key] = value
                    else:
                        processed_config[key] = value
                # Old format: 'Service': 'Port:protocol'
                else:
                    parts = value.split(":")
                    if len(parts) >= 2:
                        try:
                            port = int(parts[0])
                            protocol = (
                                parts[1].upper()
                                if parts[1].upper() in ["TCP", "UDP"]
                                else "TCP"
                            )
                            processed_config[key] = {"port": port, "protocol": protocol}
                        except ValueError:
                            processed_config[key] = value
                    else:
                        processed_config[key] = value
            # Simpler format: 'Service': Port (assumed TCP)
            elif isinstance(value, int):
                processed_config[key] = {"port": value, "protocol": "TCP"}
            else:
                processed_config[key] = value

        return processed_config
    except Exception as e:
        logger.error(f"Failed to load config file: {e}")
        return {}


def save_config(config_data):
    """Save configuration file."""
    try:
        with file_lock:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error(f"Failed to save config file: {e}")
        return False


def load_hidden_ports():
    """Load list of hidden ports."""
    try:
        if os.path.exists(HIDDEN_PORTS_FILE):
            with open(HIDDEN_PORTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        return []
    except Exception as e:
        logger.error(f"Failed to load hidden ports config: {e}")
        return []


def save_hidden_ports(hidden_ports):
    """Save list of hidden ports."""
    try:
        with file_lock:
            with open(HIDDEN_PORTS_FILE, "w", encoding="utf-8") as f:
                json.dump(hidden_ports, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error(f"Failed to save hidden ports config: {e}")
        return False


def load_users():
    """Load user configuration."""
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}
    except Exception as e:
        logger.error(f"Failed to load user config: {e}")
        return {}


def save_users(users):
    """Save user configuration."""
    try:
        with file_lock:
            with open(USERS_FILE, "w", encoding="utf-8") as f:
                json.dump(users, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error(f"Failed to save user config: {e}")
        return False


def hash_password(password):
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(password, hashed):
    """Check a password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def init_users():
    """Initialize default user configuration."""
    if not os.path.exists(USERS_FILE):
        default_users = {
            os.getenv("ADMIN_USERNAME", "admin"): {
                "password": hash_password(os.getenv("ADMIN_PASSWORD", "admin123")),
                "role": "admin",
                "created_at": datetime.now().isoformat(),
            }
        }

        save_users(default_users)
        print(f"Default user config file created: {USERS_FILE}")
        print(f"Default user: {os.getenv('ADMIN_USERNAME', 'admin')}, password: {os.getenv('ADMIN_PASSWORD', 'admin123')}")
    else:
        print(f"User config file already exists: {USERS_FILE}")


def login_required(f):
    """Decorator to require user login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "Login required"}), 401
        return f(*args, **kwargs)

    return decorated_function


# Initialize configuration
init_config()
init_users()
config = load_config()  # Global configuration variable


class PortMonitor:
    """Port monitoring class."""

    def __init__(self):
        try:
            self.docker_client = docker.from_env()
            logger.info("Docker client connection successful")
        except Exception as e:
            logger.error(f"Docker client connection failed: {e}")
            self.docker_client = None

        self.container_cache = {}
        self.cache_timestamp = 0
        self.cache_ttl = 30 # Cache TTL in seconds

        # Default common ports for display
        self.default_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            67: "DHCP Server",
            68: "DHCP Client",
            69: "TFTP",
            80: "HTTP",
            110: "POP3",
            123: "NTP",
            135: "RPC",
            137: "NetBIOS Name",
            138: "NetBIOS Datagram",
            139: "NetBIOS Session",
            143: "IMAP",
            161: "SNMP",
            389: "LDAP",
            443: "HTTPS",
            445: "SMB",
            465: "SMTPS",
            514: "Syslog",
            587: "SMTP",
            631: "IPP",
            636: "LDAPS",
            993: "IMAPS",
            995: "POP3S",
            1433: "SQL Server",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP Proxy",
            8443: "HTTPS Alt",
            9200: "Elasticsearch",
            27017: "MongoDB",
        }

    def get_docker_ports(self):
        """
        Retrieves container port mapping information via the Docker API.
        Only retrieves mapped ports for non-host network mode containers.
        Host mode container ports are handled by get_host_ports and netstat.
        """
        ports_info = []
        if not self.docker_client:
            return ports_info
        try:
            containers = self.docker_client.containers.list()
            for container in containers:
                container_name = container.name
                
                # Skip host network mode containers; they are handled by get_host_ports
                network_mode = container.attrs.get("HostConfig", {}).get(
                    "NetworkMode", ""
                )
                if network_mode == "host":
                    continue 

                ports = container.attrs.get("NetworkSettings", {}).get("Ports", {})
                
                for container_port, host_bindings in ports.items():
                    # Process non-host containers with port mappings
                    if host_bindings:
                        for binding in host_bindings:
                            # Ensure HostPort exists and is an integer
                            if "HostPort" in binding and binding["HostPort"]:
                                try:
                                    host_port = int(binding["HostPort"])
                                    ports_info.append(
                                        {
                                            "port": host_port,
                                            "container_name": container_name,
                                            "container_port": container_port, # Format like "80/tcp"
                                            "type": "docker_mapped",
                                            # Attempt to extract protocol from container port spec
                                            "protocol": container_port.split('/')[-1].upper() if '/' in container_port else 'TCP', 
                                        }
                                    )
                                except ValueError:
                                    logger.warning(f"Invalid HostPort '{binding['HostPort']}' for container {container_name}")

        except Exception as e:
            logger.error(f"Failed to retrieve Docker port information: {e}")
        return ports_info

    def get_host_ports(self):
        """
        Retrieves host listening port information via netstat,
        and associates them with host network mode Docker containers.
        """
        port_info = {}
        port_protocols = {}
        # Get cached host network container info (key for associating host containers)
        host_containers = self.get_host_network_containers_cached() 
        try:
            # -t: TCP, -u: UDP, -l: Listening, -n: Numeric
            result = subprocess.run(
                ["netstat", "-tuln"], capture_output=True, text=True, check=True
            )
            for line in result.stdout.split("\n"):
                line = line.strip()
                if not line or line.startswith("Proto"):
                    continue
                
                # Use regex for more precise line parsing
                parts = re.split(r'\s+', line)
                
                # Needs at least 4 parts: Proto Recv-Q Send-Q Local Address
                if len(parts) < 4:
                    continue

                protocol = parts[0].upper().strip() # e.g., TCP, TCP6, UDP, UDP6
                local_address = parts[3] # e.g., 0.0.0.0:80, [::]:443

                # Only process listening TCP and UDP ports
                if not ("LISTEN" in line or protocol.startswith("UDP")):
                     continue 

                # Extract protocol type and IP version
                if protocol.endswith("6"):
                    protocol_type = protocol[:-1] # TCP6 -> TCP, UDP6 -> UDP
                    ip_version = "IPv6"
                else:
                    protocol_type = protocol
                    ip_version = "IPv4"
                
                # Extract port number
                port = None
                if ":" in local_address:
                    if local_address.startswith("[") and "]:" in local_address:
                        # IPv6 address: [::]:443
                        port_part = local_address.split("]:")[-1]
                    elif local_address.count(":") == 1 and protocol_type in ["TCP", "UDP"]:
                        # IPv4 address: 0.0.0.0:80
                        port_part = local_address.split(":")[-1]
                    else:
                        # Complex or unknown format, skip
                        continue
                    
                    try:
                        port = int(port_part)
                        if not (1 <= port <= 65535):
                            port = None
                    except ValueError:
                        port = None
                
                if port is None:
                    continue
                
                container_name = None
                # Check if this port is exposed by any host network container
                for container_info in host_containers.values():
                    if port in container_info["exposed_ports"]:
                        container_name = container_info["name"]
                        break

                # Record port and protocol details
                if port not in port_protocols:
                    port_protocols[port] = {
                        "protocols": set(),
                        "ip_versions": set(),
                    }
                port_protocols[port]["protocols"].add(protocol_type)
                port_protocols[port]["ip_versions"].add(ip_version)

                # Record port information (only record the first occurrence, supplement protocol later)
                if port not in port_info:
                    port_info[port] = {
                        "port": port,
                        "protocol": protocol_type, # Initial protocol
                        "address": local_address,
                        "service_name": self.get_service_name(port),
                        "container_name": container_name, # Associated host network container name
                    }

            # Normalize protocol display for IPv4/IPv6 and TCP/UDP
            for port, info in port_info.items():
                protocols = port_protocols[port]["protocols"]
                ip_versions = port_protocols[port]["ip_versions"]
                
                final_protocols = []
                for protocol in sorted(protocols):
                    # If listening on both IPv4 and IPv6, usually just display TCP/UDP
                    if "IPv4" in ip_versions and "IPv6" in ip_versions and len(protocols) == 1:
                        final_protocols.append(protocol)
                    elif "IPv6" in ip_versions and "IPv4" not in ip_versions:
                        final_protocols.append(protocol + "6")
                    elif "IPv4" in ip_versions and "IPv6" not in ip_versions:
                        final_protocols.append(protocol)
                    else:
                        final_protocols.append(protocol)

                # Avoid duplicate protocol names and sort alphabetically
                info["protocol"] = "/".join(sorted(list(set(final_protocols))))

        except subprocess.CalledProcessError as e:
            logger.error(f"netstat execution failed: {e.stderr.strip()}")
        except Exception as e:
            logger.error(f"Failed to retrieve host port information: {e}")
        return port_info

    def get_service_name(self, port):
        """Map a port number to a configured or default service name."""
        config_ports = {}
        for k, v in config.items():
            if isinstance(v, dict) and "port" in v:
                config_ports[k] = v["port"]
            elif isinstance(v, int):
                config_ports[k] = v
        
        # Look up service name from configuration
        port_to_service = {v: k for k, v in config_ports.items()}
        if port in port_to_service:
            return port_to_service[port]
        
        # Look up service name from default list
        if port in self.default_ports:
            return self.default_ports[port]
            
        return "Unknown Service"

    def get_host_network_containers_cached(self):
        """
        Get info (name, ID, exposed ports) for containers running in host network mode.
        Uses a cache to avoid frequent Docker API calls.
        """
        current_time = time.time()
        # Check cache freshness
        if (
            current_time - self.cache_timestamp
        ) < self.cache_ttl and self.container_cache:
            return self.container_cache

        self.container_cache = {}
        if not self.docker_client:
            return self.container_cache

        try:
            containers = self.docker_client.containers.list()
            for container in containers:
                network_mode = container.attrs.get("HostConfig", {}).get(
                    "NetworkMode", ""
                )
                if network_mode == "host":
                    container_info = {
                        "name": container.name,
                        "id": container.id[:12],
                        "exposed_ports": set(),
                        "potential_ports": set(),
                    }
                    
                    # 1. Ports from ExposedPorts config
                    try:
                        exposed_ports = container.attrs.get("Config", {}).get(
                            "ExposedPorts", {}
                        )
                        if exposed_ports:
                            for port_spec in exposed_ports.keys():
                                if "/" in port_spec:
                                    port_num = int(port_spec.split("/")[0])
                                    container_info["exposed_ports"].add(port_num)
                    except Exception:
                        pass

                    # 2. Ports from Healthcheck command (if available)
                    try:
                        healthcheck = container.attrs.get("Config", {}).get(
                            "Healthcheck", {}
                        )
                        if healthcheck and "Test" in healthcheck:
                            test_cmd = str(healthcheck["Test"])
                            # Regex to find port numbers in 'host:port' or 'ip:port' format
                            port_matches = re.findall(
                                r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0):?(\d{1,5})",
                                test_cmd,
                            )
                            for port_str in port_matches:
                                p = int(port_str)
                                if 1 <= p <= 65535:
                                    container_info["potential_ports"].add(p)
                    except Exception:
                        pass

                    # Merge all identified ports
                    container_info["exposed_ports"].update(
                        container_info["potential_ports"]
                    )
                    self.container_cache[container.name] = container_info
        except Exception:
            # Handle potential Docker API errors gracefully
            pass
            
        self.cache_timestamp = current_time
        return self.container_cache

    def get_port_analysis(self, start_port=1, end_port=65535, protocol_filter=None):
        """
        Performs the main port analysis, combining Docker mapped ports and host netstat data.
        Generates port cards for used ports, unknown ranges, and available gaps.
        """
        docker_ports = self.get_docker_ports()
        host_ports_info = self.get_host_ports()
        port_cards = []
        tcp_ports = set()
        udp_ports = set()
        port_protocol_map = {}

        # Aggregate host ports and protocols
        for port, info in host_ports_info.items():
            if port < start_port or port > end_port:
                continue
            protocol = info.get("protocol", "TCP")
            port_protocol_map[port] = protocol
            if "TCP" in protocol.upper():
                tcp_ports.add(port)
            if "UDP" in protocol.upper():
                udp_ports.add(port)

        # Aggregate Docker mapped ports
        docker_port_map = {}
        for port_info in docker_ports:
            if port_info["port"]:
                port = port_info["port"]
                if port < start_port or port > end_port:
                    continue
                # Mapped ports are always considered active
                tcp_ports.add(port) 
                docker_port_map[port] = port_info
                if port not in port_protocol_map:
                    port_protocol_map[port] = "TCP" # Default protocol if not in netstat output

        # Apply protocol filtering
        if protocol_filter == "TCP":
            filtered_ports = tcp_ports
        elif protocol_filter == "UDP":
            filtered_ports = udp_ports
        else:
            filtered_ports = tcp_ports.union(udp_ports)

        sorted_ports = sorted(filtered_ports)
        port_data_list = []

        # Create base port data list
        for port in sorted_ports:
            protocol = port_protocol_map.get(port, "TCP")
            if protocol_filter and protocol_filter.upper() not in protocol.upper():
                continue

            config_service_type = None
            config_service_name = None
            # Check for configured service name
            for service_name, service_config in config.items():
                if (
                    isinstance(service_config, dict)
                    and service_config.get("port") == port
                ):
                    config_service_type = service_config.get("service_type")
                    config_service_name = service_name
                    break

            if port in docker_port_map:
                # Docker mapped port (non-host network)
                docker_info = docker_port_map[port]
                source = (
                    config_service_type
                    if config_service_type in ["docker", "host"]
                    else "docker"
                )
                card_data = {
                    "port": port,
                    "type": "used",
                    "source": source,
                    "protocol": protocol,
                    "container": docker_info["container_name"],
                    "process": f"Docker: {docker_info['container_name']}",
                    "image": docker_info.get("image", ""),
                    "container_port": docker_info["container_port"],
                    "service_name": config_service_name
                    or docker_info["container_name"],
                }
            else:
                # Host port (system process or host network Docker)
                host_info = host_ports_info.get(port, {})
                is_host_container = bool(host_info.get("container_name"))
                if config_service_type in ["docker", "host"]:
                    source = config_service_type
                elif is_host_container:
                    source = "docker"
                else:
                    source = "system"

                card_data = {
                    "port": port,
                    "type": "used",
                    "source": source,
                    "protocol": protocol,
                    "service_name": config_service_name
                    or host_info.get("service_name", "Unknown Service"),
                    "container": host_info.get("container_name"),
                    "is_host_network": is_host_container,
                }
            port_data_list.append(card_data)

        # Merge logic for unknown ports and add gaps
        i = 0
        while i < len(port_data_list):
            current = port_data_list[i]
            # Merge consecutive 'Unknown Service' ports into a range card
            if current["service_name"] == "Unknown Service":
                consecutive = [current]
                j = i + 1
                while (
                    j < len(port_data_list)
                    and port_data_list[j]["service_name"] == "Unknown Service"
                    and port_data_list[j]["port"] == port_data_list[j - 1]["port"] + 1
                ):
                    consecutive.append(port_data_list[j])
                    j += 1
                if len(consecutive) >= 2:
                    merged = {
                        "type": "unknown_range",
                        "start_port": consecutive[0]["port"],
                        "end_port": consecutive[-1]["port"],
                        "port_count": len(consecutive),
                        "source": consecutive[0]["source"],
                        "protocol": consecutive[0]["protocol"],
                        "service_name": "Unknown Service",
                        "container": consecutive[0].get("container"),
                        "is_host_network": consecutive[0].get("is_host_network", False),
                    }
                    port_cards.append(merged)
                    i = j
                else:
                    port_cards.append(current)
                    i += 1
            else:
                port_cards.append(current)
                i += 1

            # Insert gap cards between used/range cards
            if port_cards:
                last_card = port_cards[-1]
                current_last_port = (
                    last_card["end_port"]
                    if last_card["type"] == "unknown_range"
                    else last_card.get("port")
                )

                next_port = (
                    port_data_list[i]["port"] if i < len(port_data_list) else None
                )

                if next_port:
                    gap = next_port - current_last_port - 1
                    if gap > 0:
                        port_cards.append(
                            {
                                "type": "gap",
                                "start_port": current_last_port + 1,
                                "end_port": next_port - 1,
                                "available_count": gap,
                            }
                        )

        # Handle final gap after the last used/range port
        if port_cards:
            last_card = port_cards[-1]
            if last_card["type"] == "gap":
                # Extend the last gap to the end_port if needed
                if last_card["end_port"] < end_port:
                    last_card["end_port"] = end_port
                    last_card["available_count"] = (
                        last_card["end_port"] - last_card["start_port"] + 1
                    )
            else:
                last_port = (
                    last_card["end_port"]
                    if last_card["type"] == "unknown_range"
                    else last_card.get("port", 0)
                )
                if last_port < end_port:
                    port_cards.append(
                        {
                            "type": "gap",
                            "start_port": last_port + 1,
                            "end_port": end_port,
                            "available_count": end_port - last_port,
                        }
                    )
        else:
            # Entire range is a gap
            port_cards.append(
                {
                    "type": "gap",
                    "start_port": start_port,
                    "end_port": end_port,
                    "available_count": end_port - start_port + 1,
                }
            )

        docker_container_count = len(
            set(
                p.get("container", p.get("container_name", ""))
                for p in port_cards
                if p.get("source") == "docker" and p.get("container")
            )
        )
        total_range = end_port - start_port + 1
        # Calculate total available ports
        available_ports = (
            total_range - len(filtered_ports)
            if protocol_filter
            else total_range - len(tcp_ports.union(udp_ports))
        )

        # Apply hidden ports filter
        hidden_ports = load_hidden_ports()
        if hidden_ports:
            final_cards = []
            for card in port_cards:
                should_hide = False
                if card["type"] == "used" and card["port"] in hidden_ports:
                    should_hide = True
                elif card["type"] == "unknown_range":
                    # If any port in the range is hidden, hide the whole range card
                    for p in range(card["start_port"], card["end_port"] + 1):
                        if p in hidden_ports:
                            should_hide = True
                            break
                if not should_hide:
                    final_cards.append(card)
            port_cards = final_cards

        return {
            "port_cards": port_cards,
            "total_used": len(filtered_ports),
            "total_available": available_ports,
            "tcp_used": len(tcp_ports),
            "udp_used": len(udp_ports),
            "docker_containers": docker_container_count,
            "hidden_ports": hidden_ports,
        }


port_monitor = PortMonitor()


@app.route("/")
def index():
    return render_template("index.html")


# Authentication Routes
@app.route("/api/auth/login", methods=["POST"])
def api_login():
    try:
        data = request.get_json()
        if not data or "username" not in data or "password" not in data:
            return jsonify({"success": False, "error": "Username and password required"}), 400

        username = data["username"].strip()
        password = data["password"]
        users = load_users()

        if username not in users:
            return jsonify({"success": False, "error": "Invalid username or password"}), 401

        if not check_password(password, users[username]["password"]):
            return jsonify({"success": False, "error": "Invalid username or password"}), 401

        session["logged_in"] = True
        session["username"] = username
        session["role"] = users[username].get("role", "user")

        return jsonify(
            {
                "success": True,
                "message": "Login successful",
                "user": {"username": username, "role": session["role"]},
            }
        )
    except Exception as e:
        logger.error(f"Login failed: {e}")
        return jsonify({"success": False, "error": "Login failed"}), 500


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"success": True, "message": "Logged out successfully"})


@app.route("/api/auth/check")
def api_check_auth():
    """Check current authentication status."""
    if session.get("logged_in"):
        return jsonify(
            {
                "success": True,
                "logged_in": True,
                "user": {
                    "username": session.get("username"),
                    "role": session.get("role"),
                },
            }
        )
    return jsonify({"success": True, "logged_in": False})


@app.route("/api/auth/users", methods=["GET"])
@login_required
def api_get_users():
    """Retrieve list of users (Admin only)."""
    if session.get("role") != "admin":
        return jsonify({"success": False, "error": "Permission denied"}), 403

    try:
        users = load_users()
        user_list = [
            {
                "username": k,
                "role": v.get("role", "user"),
                "created_at": v.get("created_at"),
            }
            for k, v in users.items()
        ]
        return jsonify({"success": True, "users": user_list})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/auth/users", methods=["POST"])
@login_required
def api_create_user():
    """Create a new user (Admin only)."""
    if session.get("role") != "admin":
        return jsonify({"success": False, "error": "Permission denied"}), 403

    try:
        data = request.get_json()
        username = data.get("username", "").strip()
        password = data.get("password", "")
        role = data.get("role", "user")

        if not username or len(password) < 6:
            return jsonify(
                {"success": False, "error": "Username required, password min 6 chars"}
            ), 400

        users = load_users()
        if username in users:
            return jsonify({"success": False, "error": "User already exists"}), 400

        users[username] = {
            "password": hash_password(password),
            "role": role,
            "created_at": datetime.now().isoformat(),
        }
        if save_users(users):
            return jsonify({"success": True, "message": "User created successfully"})
        return jsonify({"success": False, "error": "Failed to save user"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/auth/users/<username>", methods=["DELETE"])
@login_required
def api_delete_user(username):
    """Delete a user (Admin only)."""
    if session.get("role") != "admin":
        return jsonify({"success": False, "error": "Permission denied"}), 403
    # Prevent self-deletion
    if username == session.get("username"):
        return jsonify({"success": False, "error": "Cannot delete self"}), 400

    try:
        users = load_users()
        if username not in users:
            return jsonify({"success": False, "error": "User not found"}), 404

        # Prevent deleting the last admin
        if users[username].get("role") == "admin":
            admin_count = sum(1 for u in users.values() if u.get("role") == "admin")
            if admin_count <= 1:
                return jsonify(
                    {"success": False, "error": "Cannot delete the last administrator"}
                ), 400

        del users[username]
        if save_users(users):
            return jsonify({"success": True, "message": "User deleted successfully"})
        return jsonify({"success": False, "error": "Failed to save user"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/auth/change-password", methods=["POST"])
@login_required
def api_change_password():
    """Change current user's password."""
    try:
        data = request.get_json()
        current_pw = data.get("current_password")
        new_pw = data.get("new_password")
        username = session.get("username")

        if not current_pw or not new_pw or len(new_pw) < 6:
            return jsonify({"success": False, "error": "Invalid parameters or new password too short"}), 400

        users = load_users()
        if username not in users:
            session.clear()
            return jsonify({"success": False, "error": "User not found"}), 401

        if not check_password(current_pw, users[username]["password"]):
            return jsonify({"success": False, "error": "Incorrect current password"}), 401

        if check_password(new_pw, users[username]["password"]):
            return jsonify({"success": False, "error": "New password cannot be the same as old password"}), 400

        users[username]["password"] = hash_password(new_pw)
        users[username]["password_changed_at"] = datetime.now().isoformat()

        if save_users(users):
            return jsonify({"success": True, "message": "Password changed successfully"})
        return jsonify({"success": False, "error": "Failed to save password"}), 500
    except Exception as e:
        logger.error(f"Change password failed: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# Port Analysis Routes
@app.route("/api/ports")
def api_ports():
    """Get port analysis data with optional filtering and search."""
    try:
        protocol_filter = request.args.get("protocol", "").upper()
        if protocol_filter not in ["TCP", "UDP"]:
            protocol_filter = None

        try:
            start = int(request.args.get("start_port", 1))
            end = int(request.args.get("end_port", 65535))
            start = max(1, start)
            end = min(65535, end)
            if start > end:
                start, end = end, start
        except:
            start, end = 1, 65535

        port_data = port_monitor.get_port_analysis(
            start_port=start, end_port=end, protocol_filter=protocol_filter
        )

        search = request.args.get("search", "").strip().lower()
        if search:
            original_total_used = port_data["total_used"]

            filtered_cards = []
            for card in port_data["port_cards"]:
                searchable_text = ""
                is_match = False
                
                # Check for port number match if search is a digit
                if search.isdigit():
                    search_port = int(search)
                else:
                    search_port = -1

                if card["type"] == "used":
                    searchable_text = " ".join(
                        [
                            str(card.get("port", "")),
                            card.get("process", "") or "",
                            card.get("service_name", "") or "",
                            card.get("container", "") or "",
                            card.get("protocol", "") or "",
                        ]
                    ).lower()
                    is_match = search in searchable_text or card.get("port") == search_port

                elif card["type"] == "unknown_range":
                    searchable_text = " ".join(
                        [
                            f"{card.get('start_port', '')}-{card.get('end_port', '')}",
                            str(card.get("start_port", "")),
                            str(card.get("end_port", "")),
                            card.get("service_name", "") or "",
                            card.get("container", "") or "",
                            card.get("protocol", "") or "",
                        ]
                    ).lower()
                    is_match = search in searchable_text
                    if search_port != -1:
                        card_start_port = card.get("start_port", 0)
                        card_end_port = card.get("end_port", 0)
                        if card_start_port <= search_port <= card_end_port:
                            is_match = True

                elif card["type"] == "gap":
                    searchable_text = " ".join(
                        [
                            f"{card.get('start_port', '')}-{card.get('end_port', '')}",
                            str(card.get("start_port", "")),
                            str(card.get("end_port", "")),
                            "available",
                            "unused",
                        ]
                    ).lower()
                    is_match = search in searchable_text
                    if search_port != -1:
                        gap_start_port = card.get("start_port", 0)
                        gap_end_port = card.get("end_port", 0)
                        if gap_start_port <= search_port <= gap_end_port:
                            is_match = True

                if is_match:
                    filtered_cards.append(card)

            filtered_cards = sorted(
                filtered_cards, key=lambda x: x.get("port", x.get("start_port", 0))
            )
            
            # Recalculate used count based on filter
            filtered_used_count = len(
                [
                    card
                    for card in filtered_cards
                    if card["type"] in ["used", "unknown_range"]
                ]
            )

            port_data["port_cards"] = filtered_cards
            port_data["total_used"] = filtered_used_count
            # Total available remains relative to the full range (1-65535) for consistency
            port_data["total_available"] = max(0, 65535 - original_total_used)

        return jsonify({"success": True, "data": port_data})
    except Exception as e:
        logger.error(f"API call failed: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/config")
def api_get_config():
    """Get processed config data."""
    return jsonify(config)


@app.route("/api/config/raw")
def api_get_raw_config():
    """Get raw config data from file."""
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return jsonify(json.load(f))


@app.route("/api/config", methods=["POST"])
@login_required
def api_save_config():
    """Save or update configuration entry (Login required)."""
    global config
    try:
        data = request.get_json()
        
        # Handle single port/service update
        if "port" in data and "service_name" in data:
            port = data["port"]
            name = data["service_name"]
            stype = data.get("service_type", "host")
            current = load_config()

            # Remove existing entry for this port to ensure uniqueness
            keys_to_del = []
            for k, v in current.items():
                p = (
                    v["port"]
                    if isinstance(v, dict)
                    else (v if isinstance(v, int) else None)
                )
                if p == port:
                    keys_to_del.append(k)
            for k in keys_to_del:
                del current[k]

            # Add the new/updated entry
            current[name] = {"port": port, "protocol": "TCP", "service_type": stype}
            
            # Convert back to raw string format for saving
            raw_to_save = {}
            for k, v in current.items():
                if isinstance(v, dict):
                    new_key = f"{k}:{v.get('service_type', 'host')}"
                    raw_to_save[new_key] = f"{v['port']}:{v['protocol'].lower()}"
                else:
                    raw_to_save[k] = v
            
            if save_config(raw_to_save):
                config = load_config()
                return jsonify({"success": True})
        
        # Handle full config overwrite (if data is raw config)
        else:
            if save_config(data):
                config = load_config()
                return jsonify({"success": True})
                
        return jsonify({"error": "Failed to save config"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/refresh")
@login_required
def api_refresh():
    """Refresh the port monitor's cache and return new port data."""
    # Re-initialize the monitor to clear cache and re-check Docker client
    port_monitor.__init__() 
    return api_ports()


@app.route("/api/hidden-ports")
def api_get_hidden_ports():
    """Get the list of hidden ports."""
    return jsonify({"success": True, "data": load_hidden_ports()})


@app.route("/api/hidden-ports", methods=["POST", "DELETE"])
@login_required
def api_manage_hidden_port():
    """Add (POST) or remove (DELETE) a single port from the hidden list."""
    try:
        data = request.get_json()
        port = data.get("port")
        hidden = load_hidden_ports()

        if request.method == "POST":
            if port not in hidden:
                hidden.append(port)
                hidden.sort()
        elif request.method == "DELETE":
            if port in hidden:
                hidden.remove(port)

        if save_hidden_ports(hidden):
            return jsonify({"success": True})
        return jsonify({"error": "Failed to save hidden ports"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/hidden-ports/batch", methods=["POST", "DELETE"])
@login_required
def api_batch_hidden_ports():
    """Add (POST) or remove (DELETE) a list of ports from the hidden list."""
    try:
        data = request.get_json()
        ports = data.get("ports", [])
        hidden = load_hidden_ports()

        changed = False
        if request.method == "POST":
            # Add all new ports
            for p in ports:
                if p not in hidden:
                    hidden.append(p)
                    changed = True
            hidden.sort()
        elif request.method == "DELETE":
            # Remove existing ports
            initial_len = len(hidden)
            hidden = [p for p in hidden if p not in ports]
            if len(hidden) != initial_len:
                changed = True

        if changed:
            if save_hidden_ports(hidden):
                return jsonify({"success": True})
            return jsonify({"error": "Failed to save hidden ports"}), 500
            
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("DOCKPORTS_PORT", 7577))
    )
    parser.add_argument("--host", default=os.environ.get("DOCKPORTS_HOST", "0.0.0.0"))
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    app.run(host=args.host, port=args.port, debug=args.debug)