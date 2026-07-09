import socket
import base64
import json
from urllib.parse import urlparse
import concurrent.futures
import logging
import time
import re

# تنظیمات لاگ
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fix_base64_padding(s):
    """اصلاح پدینگ رشته‌های بیس۶۴"""
    s = s.strip()
    return s + '=' * (-len(s) % 4)

def parse_config(config_str):
    """استخراج پروتکل، آدرس و پورت از رشته کانفیگ با پشتیبانی از IPv6"""
    config_str = config_str.strip()
    if not config_str:
        return None, None, None

    try:
        if config_str.startswith('vmess://'):
            b64_data = config_str[8:].split('?')[0]
            json_str = base64.b64decode(fix_base64_padding(b64_data)).decode('utf-8')
            data = json.loads(json_str)
            address = data.get('add', '').strip('[]')
            return 'tcp', address, int(data.get('port'))
            
        elif config_str.startswith(('vless://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://', 'tuic://')):
            parsed = urlparse(config_str)
            host_port = parsed.netloc.split('@')[-1]
            
            if host_port.startswith('['):
                match = re.match(r'\[(.*?)\]:(\d+)', host_port)
                if match:
                    address, port = match.group(1), match.group(2)
                else:
                    return None, None, None
            else:
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

def resolve_dns_with_timeout(hostname, timeout=2):
    """حل کردن نام دامنه به آی‌پی با در نظر گرفتن تایم‌اوت برای جلوگیری از بلوکه شدن ترد"""
    # اگر ورودی از قبل آی‌پی باشد، نیازی به کارهای اضافه نیست
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, hostname)
            # برگرداندن family به همراه hostname برای استفاده در ساخت سوکت
            return family, hostname
        except OSError:
            continue
            
    # استفاده از ترفند ست کردن تایم‌اوت پیش‌فرض سوکت برای تابع getaddrinfo
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(hostname, None)
        # استخراج family (AF_INET یا AF_INET6) و آی‌پی
        family = infos[0][0]
        ip_address = infos[0][4][0]
        return family, ip_address
    except (socket.gaierror, socket.timeout, OSError):
        return None, None
    finally:
        socket.setdefaulttimeout(old_timeout)

def test_connection(address, port, protocol='tcp', timeout=3):
    """تست اتصال TCP یا UDP به سرور و محاسبه زمان پاسخ دقیق لایه ۴"""
    # ۱. تست سریع DNS با تایم‌اوت مشخص برای جلوگیری از فریز شدن
    family, ip_address = resolve_dns_with_timeout(address, timeout=timeout)
    if not ip_address:
        return False, None

    # شروع محاسبه زمان دقیق RTT پس از عبور از مرحله DNS
    start_time = time.perf_counter()
    try:
        if protocol == 'tcp':
            # استفاده از family استخراج شده به جای AF_INET ثابت (حیاتی برای IPv6)
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip_address, port))
                rtt = int((time.perf_counter() - start_time) * 1000)
                return True, rtt
                
        elif protocol == 'udp':
            # استفاده از family استخراج شده برای UDP
            with socket.socket(family, socket.SOCK_DGRAM) as s:
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
    """پردازش یک کانفیگ: پارس و تست اتصال"""
    protocol, address, port = parse_config(config_str)
    if not address or not port:
        return config_str, False, None
    
    is_alive, rtt = test_connection(address, port, protocol, timeout)
    return config_str, is_alive, rtt

def ping_configs(input_file='configs/proxy_configs.txt', output_file='configs/healthy_configs.txt', timeout=3, max_workers=100, max_rtt=2000):
    """تابع اصلی: خواندن فایل، پینگ کردن و ذخیره کانفیگ‌های سالم"""
    logger.info(f"شروع پینگ‌گیر. در حال خواندن از {input_file}...")
    logger.info(f"تنظیمات: Timeout={timeout}s | Max Workers={max_workers} | Max RTT={max_rtt}ms")
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            configs = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"فایل ورودی {input_file} پیدا نشد.")
        return

    logger.info(f"تعداد {len(configs)} کانفیگ برای تست پیدا شد.")
    healthy_configs = []
    dropped_slow = 0  
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_config = {executor.submit(process_config, config, timeout): config for config in configs}
        
        for i, future in enumerate(concurrent.futures.as_completed(future_to_config)):
            config_str, is_alive, rtt = future.result()
            
            if is_alive:
                if rtt is None or rtt <= max_rtt:
                    healthy_configs.append((config_str, rtt))
                else:
                    dropped_slow += 1
            
            if (i + 1) % 100 == 0 or (i + 1) == len(configs):
                logger.info(f"پیشرفت: {i + 1}/{len(configs)} تست شد. | سالم: {len(healthy_configs)} | حذف‌شده (کند): {dropped_slow}")

    # مرتب‌سازی بر اساس کمترین پینگ
    healthy_configs.sort(key=lambda x: x[1] if x[1] is not None else 9999)

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for config, rtt in healthy_configs:
                f.write(config + '\n')
        logger.info(f"✅ با موفقیت {len(healthy_configs)} کانفیگ سالم در فایل {output_file} ذخیره شد.")
        if dropped_slow > 0:
            logger.info(f"⚠️ تعداد {dropped_slow} کانفیگ به دلیل پینگ بالاتر از {max_rtt}ms حذف شدند.")
    except Exception as e:
        logger.error(f"خطا در نوشتن فایل {output_file}: {e}")

if __name__ == "__main__":
    ping_configs(timeout=3, max_workers=100, max_rtt=2000)
