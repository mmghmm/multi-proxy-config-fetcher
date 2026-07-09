import socket
import base64
import json
from urllib.parse import urlparse
import concurrent.futures
import logging
import time

# تنظیمات لاگ
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fix_base64_padding(s):
    """اصلاح پدینگ رشته‌های بیس۶۴"""
    s = s.strip()
    return s + '=' * (-len(s) % 4)

def parse_config(config_str):
    """استخراج پروتکل، آدرس و پورت (شناسایی و تفکیک هوشمند IPv6)"""
    config_str = config_str.strip()
    if not config_str:
        return None, None, None

    try:
        if config_str.startswith('vmess://'):
            b64_data = config_str[8:].split('?')[0]
            json_str = base64.b64decode(fix_base64_padding(b64_data)).decode('utf-8')
            data = json.loads(json_str)
            address = data.get('add', '').strip()
            
            # تشخیص کانفیگ‌های IPv6 در VMess
            if ':' in address or address.startswith('['):
                return 'ipv6', None, None
                
            return 'tcp', address, int(data.get('port'))
            
        elif config_str.startswith(('vless://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://', 'tuic://')):
            parsed = urlparse(config_str)
            host_port = parsed.netloc.split('@')[-1]
            
            # تشخیص کانفیگ‌های IPv6
            if host_port.startswith('['):
                return 'ipv6', None, None
            
            if ':' in host_port:
                address, port = host_port.rsplit(':', 1)
            else:
                return None, None, None
            
            port = port.split('?')[0]
            protocol = 'udp' if config_str.startswith(('hysteria2://', 'hy2://', 'tuic://')) else 'tcp'
            return protocol, address, int(port)

    except Exception as e:
        logger.debug(f"خطا در پارس کانفیگ: {config_str[:30]}... | خطا: {e}")
        
    return None, None, None

def resolve_dns_with_timeout(hostname):
    """حل کردن نام دامنه به آی‌پی IPv4 (تایم‌اوت به صورت سراسری مدیریت می‌شود)"""
    try:
        socket.inet_pton(socket.AF_INET, hostname)
        return hostname
    except OSError:
        pass
        
    try:
        # فقط درخواست رکورد IPv4 (A) ارسال می‌شود
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
        return infos[0][4][0]
    except (socket.gaierror, socket.timeout, OSError):
        return None

def test_connection(address, port, protocol='tcp', timeout=3):
    """تست اتصال TCP یا UDP به سرور IPv4 و محاسبه زمان پاسخ RTT"""
    ip_address = resolve_dns_with_timeout(address)
    if not ip_address:
        return False, None

    start_time = time.perf_counter()
    try:
        if protocol == 'tcp':
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip_address, port))
                rtt = int((time.perf_counter() - start_time) * 1000)
                return True, rtt
                
        elif protocol == 'udp':
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.connect((ip_address, port))
                s.send(b'\x00')
                try:
                    s.recv(1)
                except socket.timeout:
                    pass 
                except ConnectionRefusedError:
                    return False, None
                
                rtt = int((time.perf_counter() - start_time) * 1000)
                return True, rtt
                
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False, None
    except Exception as e:
        logger.debug(f"خطای غیرمنتظره در تست {address}:{port} - {e}")
        return False, None

def process_config(config_str, timeout):
    """پردازش یک کانفیگ و بازگرداندن وضعیت دقیق وضعیت آن"""
    protocol, address, port = parse_config(config_str)
    
    if protocol == 'ipv6':
        return config_str, 'ipv6', None
    if not address or not port:
        return config_str, 'invalid', None
        
    is_alive, rtt = test_connection(address, port, protocol, timeout)
    if is_alive:
        return config_str, 'alive', rtt
    return config_str, 'dead', None

def ping_configs(input_file='configs/proxy_configs.txt', output_file='configs/healthy_configs.txt', timeout=3, max_workers=100, max_rtt=3000):
    """تابع اصلی: خواندن فایل، پینگ کردن و ذخیره کانفیگ‌های سالم (فقط IPv4)"""
    logger.info(f"شروع پینگ‌گیر. در حال خواندن از {input_file}...")
    logger.info(f"تنظیمات: Timeout={timeout}s | Max Workers={max_workers} | Max RTT={max_rtt}ms")
    logger.info("⚠️ کانفیگ‌های IPv6 به طور خودکار شناسایی و حذف می‌شوند.")
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            configs = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"فایل ورودی {input_file} پیدا نشد.")
        return

    logger.info(f"تعداد {len(configs)} کانفیگ برای تست پیدا شد.")
    healthy_configs = []
    dropped_slow = 0
    dropped_ipv6 = 0
    
    # حل مشکل Race Condition: تنظیم تایم‌اوت سراسری فقط یک‌بار قبل از شروع تردها
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_config = {executor.submit(process_config, config, timeout): config for config in configs}
            
            for i, future in enumerate(concurrent.futures.as_completed(future_to_config)):
                config_str, status, rtt = future.result()
                
                if status == 'ipv6':
                    dropped_ipv6 += 1
                elif status == 'alive':
                    if rtt is None or rtt <= max_rtt:
                        healthy_configs.append((config_str, rtt))
                    else:
                        dropped_slow += 1
                
                if (i + 1) % 100 == 0 or (i + 1) == len(configs):
                    logger.info(f"پیشرفت: {i + 1}/{len(configs)} | سالم: {len(healthy_configs)} | حذف‌شده (کند): {dropped_slow} | IPv6: {dropped_ipv6}")
    finally:
        # بازگرداندن وضعیت تایم‌اوت سیستم‌عامل به حالت اصلی پس از پایان کار تردها
        socket.setdefaulttimeout(old_timeout)

    # مرتب‌سازی بر اساس کمترین پینگ
    healthy_configs.sort(key=lambda x: x[1] if x[1] is not None else 9999)

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for config, rtt in healthy_configs:
                f.write(config + '\n')
        logger.info(f"✅ با موفقیت {len(healthy_configs)} کانفیگ سالم (IPv4) در فایل {output_file} ذخیره شد.")
        if dropped_slow > 0:
            logger.info(f"⚠️ تعداد {dropped_slow} کانفیگ به دلیل پینگ بالاتر از {max_rtt}ms حذف شدند.")
        if dropped_ipv6 > 0:
            logger.info(f"ℹ️ تعداد {dropped_ipv6} کانفیگ IPv6 حذف شدند.")
    except Exception as e:
        logger.error(f"خطا در نوشتن فایل {output_file}: {e}")

if __name__ == "__main__":
    ping_configs(timeout=3, max_workers=50, max_rtt=3000)
