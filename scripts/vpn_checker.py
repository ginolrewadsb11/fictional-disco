#!/usr/bin/env python3
"""
VPN Keys Checker Pro - максимально точная проверка ключей
Многоуровневая проверка: TCP → Sing-box → IP → Download → Latency
"""

import os
import base64
import asyncio
import json
import subprocess
import tempfile
import hashlib
import time
import socket
from urllib.parse import urlparse, unquote, parse_qs
from typing import Optional, Tuple
from dataclasses import dataclass
import aiohttp
from aiohttp_socks import ProxyConnector

# ============== НАСТРОЙКИ ==============
TIMEOUT_TCP = 5          # Таймаут TCP пинга
TIMEOUT_PROXY = 25       # Таймаут проверки через прокси
STARTUP_DELAY = 3        # Время запуска sing-box
MAX_CONCURRENT = 5       # Параллельных проверок (меньше = стабильнее)
MAX_LATENCY_MS = 3000    # Максимальный пинг (мс)
MIN_SPEED_KBPS = 50      # Минимальная скорость (KB/s)

# Тестовые URL
TEST_FILE_URL = "https://www.google.com/favicon.ico"  # ~1KB файл
TEST_FILE_HASH = None  # Будет вычислен динамически
IP_CHECK_URLS = [
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/ip",
    "https://icanhazip.com"
]
CONNECTIVITY_URLS = [
    "https://www.google.com/generate_204",
    "https://cp.cloudflare.com/",
    "https://connectivitycheck.gstatic.com/generate_204"
]


@dataclass
class CheckResult:
    """Результат проверки ключа"""
    key: str
    working: bool
    tcp_ok: bool = False
    proxy_ok: bool = False
    ip_changed: bool = False
    download_ok: bool = False
    latency_ms: int = 0
    speed_kbps: float = 0
    exit_ip: str = ""
    exit_country: str = ""
    error: str = ""


def decode_base64(data: str) -> str:
    """Декодирует base64"""
    for decoder in [base64.urlsafe_b64decode, base64.b64decode]:
        try:
            padding = 4 - len(data) % 4
            if padding != 4:
                data_padded = data + '=' * padding
            else:
                data_padded = data
            return decoder(data_padded).decode('utf-8', errors='ignore')
        except:
            continue
    return ""


def parse_subscription(content: str) -> list[str]:
    """Парсит подписку"""
    decoded = decode_base64(content.strip())
    if decoded:
        content = decoded
    
    protocols = ['vless://', 'vmess://', 'ss://', 'trojan://', 
                 'hysteria2://', 'hy2://', 'hysteria://', 'tuic://']
    
    keys = []
    for line in content.split('\n'):
        line = line.strip()
        if any(line.startswith(p) for p in protocols):
            keys.append(line)
    return keys


def get_key_name(key: str) -> str:
    """Извлекает имя ключа для логов"""
    if '#' in key:
        return unquote(key.split('#')[-1])[:35]
    try:
        parsed = urlparse(key)
        return f"{parsed.hostname}:{parsed.port}"[:35]
    except:
        return key[:35]


def get_host_port(key: str) -> Optional[Tuple[str, int]]:
    """Извлекает хост и порт из ключа"""
    try:
        if key.startswith('vmess://'):
            data = json.loads(decode_base64(key[8:]))
            return data.get('add'), int(data.get('port', 443))
        else:
            parsed = urlparse(key)
            if parsed.hostname and parsed.port:
                return parsed.hostname, parsed.port
    except:
        pass
    return None


# ============== SING-BOX CONFIG GENERATORS ==============

def parse_vless_to_singbox(uri: str) -> Optional[dict]:
    """VLESS → Sing-box outbound"""
    try:
        parsed = urlparse(uri)
        params = dict(p.split('=', 1) for p in parsed.query.split('&') if '=' in p)
        
        outbound = {
            "type": "vless",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port or 443,
            "uuid": parsed.username,
            "flow": params.get('flow', ''),
        }
        
        # TLS
        security = params.get('security', 'none')
        if security == 'tls':
            outbound["tls"] = {
                "enabled": True,
                "server_name": params.get('sni', parsed.hostname),
                "insecure": True,
                "utls": {"enabled": True, "fingerprint": params.get('fp', 'chrome')}
            }
        elif security == 'reality':
            outbound["tls"] = {
                "enabled": True,
                "server_name": params.get('sni', ''),
                "insecure": True,
                "utls": {"enabled": True, "fingerprint": params.get('fp', 'chrome')},
                "reality": {
                    "enabled": True,
                    "public_key": params.get('pbk', ''),
                    "short_id": params.get('sid', '')
                }
            }
        
        # Transport
        transport_type = params.get('type', 'tcp')
        if transport_type == 'ws':
            outbound["transport"] = {
                "type": "ws",
                "path": unquote(params.get('path', '/')),
                "headers": {"Host": params.get('host', parsed.hostname)}
            }
        elif transport_type == 'grpc':
            outbound["transport"] = {
                "type": "grpc",
                "service_name": params.get('serviceName', '')
            }
        elif transport_type == 'http':
            outbound["transport"] = {
                "type": "http",
                "path": unquote(params.get('path', '/'))
            }
        
        return outbound
    except:
        return None


def parse_vmess_to_singbox(uri: str) -> Optional[dict]:
    """VMess → Sing-box outbound"""
    try:
        data = json.loads(decode_base64(uri[8:]))
        
        outbound = {
            "type": "vmess",
            "tag": "proxy",
            "server": data.get('add'),
            "server_port": int(data.get('port', 443)),
            "uuid": data.get('id'),
            "security": data.get('scy', 'auto'),
            "alter_id": int(data.get('aid', 0))
        }
        
        if data.get('tls') == 'tls':
            outbound["tls"] = {
                "enabled": True,
                "server_name": data.get('sni', data.get('host', '')),
                "insecure": True
            }
        
        net = data.get('net', 'tcp')
        if net == 'ws':
            outbound["transport"] = {
                "type": "ws",
                "path": data.get('path', '/'),
                "headers": {"Host": data.get('host', '')}
            }
        elif net == 'grpc':
            outbound["transport"] = {
                "type": "grpc",
                "service_name": data.get('path', '')
            }
        elif net == 'h2':
            outbound["transport"] = {
                "type": "http",
                "path": data.get('path', '/')
            }
        
        return outbound
    except:
        return None


def parse_trojan_to_singbox(uri: str) -> Optional[dict]:
    """Trojan → Sing-box outbound"""
    try:
        parsed = urlparse(uri)
        params = dict(p.split('=', 1) for p in parsed.query.split('&') if '=' in p)
        
        outbound = {
            "type": "trojan",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port or 443,
            "password": unquote(parsed.username),
            "tls": {
                "enabled": True,
                "server_name": params.get('sni', parsed.hostname),
                "insecure": True
            }
        }
        
        transport_type = params.get('type', 'tcp')
        if transport_type == 'ws':
            outbound["transport"] = {
                "type": "ws",
                "path": unquote(params.get('path', '/'))
            }
        elif transport_type == 'grpc':
            outbound["transport"] = {
                "type": "grpc",
                "service_name": params.get('serviceName', '')
            }
        
        return outbound
    except:
        return None


def parse_ss_to_singbox(uri: str) -> Optional[dict]:
    """Shadowsocks → Sing-box outbound"""
    try:
        key_part = uri[5:].split('#')[0]
        
        if '@' in key_part:
            method_pass, host_port = key_part.rsplit('@', 1)
            decoded = decode_base64(method_pass)
            if ':' in decoded:
                method, password = decoded.split(':', 1)
            else:
                return None
            host, port = host_port.rsplit(':', 1)
        else:
            decoded = decode_base64(key_part)
            if '@' in decoded:
                method_pass, host_port = decoded.rsplit('@', 1)
                method, password = method_pass.split(':', 1)
                host, port = host_port.rsplit(':', 1)
            else:
                return None
        
        return {
            "type": "shadowsocks",
            "tag": "proxy",
            "server": host,
            "server_port": int(port),
            "method": method,
            "password": password
        }
    except:
        return None


def parse_hysteria2_to_singbox(uri: str) -> Optional[dict]:
    """Hysteria2 → Sing-box outbound"""
    try:
        parsed = urlparse(uri)
        params = dict(p.split('=', 1) for p in parsed.query.split('&') if '=' in p)
        
        return {
            "type": "hysteria2",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port or 443,
            "password": parsed.username or params.get('password', ''),
            "tls": {
                "enabled": True,
                "server_name": params.get('sni', parsed.hostname),
                "insecure": True
            }
        }
    except:
        return None


def key_to_singbox_config(key: str, socks_port: int) -> Optional[dict]:
    """Конвертирует ключ в sing-box конфиг"""
    outbound = None
    
    if key.startswith('vless://'):
        outbound = parse_vless_to_singbox(key)
    elif key.startswith('vmess://'):
        outbound = parse_vmess_to_singbox(key)
    elif key.startswith('trojan://'):
        outbound = parse_trojan_to_singbox(key)
    elif key.startswith('ss://'):
        outbound = parse_ss_to_singbox(key)
    elif key.startswith(('hysteria2://', 'hy2://')):
        outbound = parse_hysteria2_to_singbox(key)
    
    if not outbound:
        return None
    
    return {
        "log": {"level": "error"},
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": socks_port
        }],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}]
    }


# ============== ПРОВЕРКИ ==============

async def check_tcp(host: str, port: int) -> Tuple[bool, int]:
    """Быстрая TCP проверка + измерение latency"""
    start = time.time()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=TIMEOUT_TCP
        )
        latency = int((time.time() - start) * 1000)
        writer.close()
        await writer.wait_closed()
        return True, latency
    except:
        return False, 0


async def check_connectivity(session: aiohttp.ClientSession) -> Tuple[bool, str]:
    """Проверка базового соединения через прокси"""
    last_error = ""
    for url in CONNECTIVITY_URLS:
        try:
            async with session.get(url, allow_redirects=False, ssl=False) as resp:
                if resp.status in [200, 204, 301, 302, 403]:
                    return True, ""
                last_error = f"status={resp.status}"
        except asyncio.TimeoutError:
            last_error = "timeout"
        except Exception as e:
            last_error = f"{type(e).__name__}"
    return False, last_error


async def check_ip(session: aiohttp.ClientSession, my_ip: str) -> Tuple[bool, str]:
    """Проверка смены IP"""
    for url in IP_CHECK_URLS:
        try:
            async with session.get(url, ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if 'json' in url:
                        exit_ip = json.loads(text).get('ip', '')
                    else:
                        exit_ip = text.strip()
                    
                    if exit_ip and exit_ip != my_ip:
                        return True, exit_ip
        except:
            continue
    return False, ""


async def check_download(session: aiohttp.ClientSession) -> Tuple[bool, float]:
    """Проверка скачивания файла + скорость"""
    try:
        start = time.time()
        async with session.get(TEST_FILE_URL, ssl=False) as resp:
            if resp.status == 200:
                data = await resp.read()
                elapsed = time.time() - start
                if len(data) > 0 and elapsed > 0:
                    speed_kbps = (len(data) / 1024) / elapsed
                    return True, speed_kbps
    except:
        pass
    return False, 0


async def get_my_ip() -> str:
    """Получает текущий IP без прокси"""
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get("https://api.ipify.org") as resp:
                return (await resp.text()).strip()
    except:
        return ""


async def check_key_full(
    key: str, 
    semaphore: asyncio.Semaphore, 
    counter: list, 
    total: int,
    my_ip: str
) -> CheckResult:
    """Полная многоуровневая проверка ключа"""
    
    async with semaphore:
        counter[0] += 1
        num = counter[0]
        port = 20000 + (num % 5000)
        name = get_key_name(key)
        
        result = CheckResult(key=key, working=False)
        
        print(f"\n[{num}/{total}] {name}", flush=True)
        
        # === ЭТАП 1: TCP Ping ===
        host_port = get_host_port(key)
        if host_port:
            host, port_server = host_port
            tcp_ok, latency = await check_tcp(host, port_server)
            result.tcp_ok = tcp_ok
            result.latency_ms = latency
            
            if not tcp_ok:
                print(f"  ✗ TCP: сервер недоступен", flush=True)
                return result
            
            if latency > MAX_LATENCY_MS:
                print(f"  ✗ TCP: слишком высокий пинг ({latency}ms)", flush=True)
                return result
            
            print(f"  ✓ TCP: {latency}ms", flush=True)
        
        # === ЭТАП 2: Sing-box ===
        config = key_to_singbox_config(key, port)
        if not config:
            print(f"  ✗ Config: не удалось распарсить", flush=True)
            result.error = "parse_error"
            return result
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            config_path = f.name
        
        process = None
        try:
            process = subprocess.Popen(
                ['sing-box', 'run', '-c', config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            await asyncio.sleep(STARTUP_DELAY)
            
            if process.poll() is not None:
                stderr = process.stderr.read().decode() if process.stderr else ""
                print(f"  ✗ Sing-box: процесс упал ({stderr[:50]})", flush=True)
                result.error = "singbox_crash"
                return result
            
            proxy_url = f"socks5://127.0.0.1:{port}"
            timeout = aiohttp.ClientTimeout(total=TIMEOUT_PROXY, connect=10)
            
            # Используем ProxyConnector для SOCKS5
            connector = ProxyConnector.from_url(proxy_url)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                
                # === ЭТАП 3: Базовое соединение ===
                conn_ok, conn_err = await check_connectivity(session)
                if not conn_ok:
                    print(f"  ✗ Proxy: нет соединения ({conn_err})", flush=True)
                    result.error = f"no_connectivity: {conn_err}"
                    return result
                
                result.proxy_ok = True
                print(f"  ✓ Proxy: соединение есть", flush=True)
                
                # === ЭТАП 4: IP проверка ===
                ip_changed, exit_ip = await check_ip(session, my_ip)
                result.ip_changed = ip_changed
                result.exit_ip = exit_ip
                
                if ip_changed:
                    print(f"  ✓ IP: {exit_ip}", flush=True)
                else:
                    print(f"  ⚠ IP: не изменился (возможно прозрачный прокси)", flush=True)
                
                # === ЭТАП 5: Скачивание файла ===
                download_ok, speed = await check_download(session)
                result.download_ok = download_ok
                result.speed_kbps = speed
                
                if download_ok:
                    if speed >= MIN_SPEED_KBPS:
                        print(f"  ✓ Download: {speed:.1f} KB/s", flush=True)
                    else:
                        print(f"  ⚠ Download: слишком медленно ({speed:.1f} KB/s)", flush=True)
                else:
                    print(f"  ⚠ Download: не удалось скачать файл", flush=True)
            
            # === ИТОГ ===
            # Ключ рабочий если: TCP OK + Proxy OK + (IP изменился ИЛИ скачивание OK)
            result.working = result.tcp_ok and result.proxy_ok and (result.ip_changed or result.download_ok)
            
            if result.working:
                print(f"  ★ РАБОЧИЙ!", flush=True)
            else:
                print(f"  ✗ Не прошёл проверку", flush=True)
            
            return result
            
        except Exception as e:
            print(f"  ✗ Error: {e}", flush=True)
            result.error = str(e)
            return result
        finally:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except:
                    process.kill()
            try:
                os.unlink(config_path)
            except:
                pass


async def fetch_subscription(url: str) -> str:
    """Загружает подписку"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    return await resp.text()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
    return ""


async def main():
    print("=" * 60)
    print("VPN Keys Checker Pro")
    print("=" * 60)
    
    # Проверяем sing-box
    try:
        result = subprocess.run(['sing-box', 'version'], capture_output=True, text=True)
        print(f"Using: {result.stdout.split(chr(10))[0]}")
    except FileNotFoundError:
        print("ERROR: sing-box not found!")
        print("Falling back to xray...")
        # Можно добавить fallback на xray
        return
    
    # Получаем свой IP
    print("\nПолучаю текущий IP...")
    my_ip = await get_my_ip()
    if my_ip:
        print(f"Мой IP: {my_ip}")
    else:
        print("Не удалось получить IP (проверка IP будет пропущена)")
    
    # Загружаем подписки
    subscription_urls = os.environ.get('SUBSCRIPTION_URLS', '')
    
    if not subscription_urls:
        if os.path.exists('subscriptions.txt'):
            with open('subscriptions.txt', 'r') as f:
                subscription_urls = f.read()
    
    urls = [url.strip() for url in subscription_urls.split('\n') 
            if url.strip() and not url.strip().startswith('#')]
    
    if not urls:
        print("No subscription URLs found!")
        return
    
    all_keys = []
    print(f"\nЗагружаю {len(urls)} подписок...")
    
    for url in urls:
        print(f"  {url[:60]}...")
        content = await fetch_subscription(url)
        if content:
            keys = parse_subscription(content)
            print(f"    Найдено {len(keys)} ключей")
            all_keys.extend(keys)
    
    # Убираем дубликаты
    all_keys = list(set(all_keys))
    print(f"\nВсего уникальных ключей: {len(all_keys)}")
    
    if not all_keys:
        print("Ключи не найдены!")
        return
    
    # Проверяем
    print(f"\n{'=' * 60}")
    print("НАЧИНАЮ ПРОВЕРКУ")
    print(f"{'=' * 60}")
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    counter = [0]
    total = len(all_keys)
    
    tasks = [check_key_full(key, semaphore, counter, total, my_ip) for key in all_keys]
    results = await asyncio.gather(*tasks)
    
    # Фильтруем рабочие
    working = [r for r in results if r.working]
    
    # Сортируем по качеству (пинг + скорость)
    working.sort(key=lambda r: (r.latency_ms, -r.speed_kbps))
    
    # Статистика
    print(f"\n{'=' * 60}")
    print("РЕЗУЛЬТАТЫ")
    print(f"{'=' * 60}")
    print(f"Всего проверено: {len(results)}")
    print(f"TCP доступны: {sum(1 for r in results if r.tcp_ok)}")
    print(f"Proxy работает: {sum(1 for r in results if r.proxy_ok)}")
    print(f"IP изменился: {sum(1 for r in results if r.ip_changed)}")
    print(f"Download OK: {sum(1 for r in results if r.download_ok)}")
    print(f"\n★ РАБОЧИХ КЛЮЧЕЙ: {len(working)}")
    
    if working:
        # Топ-5 по скорости
        print(f"\nТоп-5 по качеству:")
        for i, r in enumerate(working[:5], 1):
            name = get_key_name(r.key)
            print(f"  {i}. {name} | {r.latency_ms}ms | {r.speed_kbps:.1f}KB/s | {r.exit_ip}")
        
        # Сохраняем
        working_keys = [r.key for r in working]
        
        with open('vpn.txt', 'w') as f:
            f.write('\n'.join(working_keys))
        
        encoded = base64.b64encode('\n'.join(working_keys).encode()).decode()
        with open('vpn_base64.txt', 'w') as f:
            f.write(encoded)
        
        # Сохраняем детальный отчёт
        report = {
            "total_checked": len(results),
            "working_count": len(working),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "keys": [
                {
                    "name": get_key_name(r.key),
                    "latency_ms": r.latency_ms,
                    "speed_kbps": round(r.speed_kbps, 1),
                    "exit_ip": r.exit_ip,
                    "key": r.key
                }
                for r in working
            ]
        }
        
        with open('vpn_report.json', 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\nСохранено:")
        print(f"  vpn.txt - {len(working)} ключей")
        print(f"  vpn_base64.txt - base64 формат")
        print(f"  vpn_report.json - детальный отчёт")
    else:
        print("\nРабочих ключей не найдено!")
        with open('vpn.txt', 'w') as f:
            f.write('')


if __name__ == '__main__':
    asyncio.run(main())
