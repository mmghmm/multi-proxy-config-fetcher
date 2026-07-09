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
            b64_data = config_str[8:].split('?')[0] # حذف پارامترهای احتمالی بعد از علامت سوال
            json_str = base64.b64decode(fix_base64_padding(b64_data)).decode('utf-8')
            data = json.loads(json_str)
            address = data.get('add', '').strip('[]') # حذف براکت‌ها اگر آی‌پی v6 بود
            return 'tcp', address, int(data.get('port'))
            
        elif config_str.startswith(('vless://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://', 'tuic://')):
            parsed = urlparse(config_str)
            # استخراج هاست و پورت با امنیت بیشتر
            host_port = parsed.netloc.split('@')[-1]
            
            # مدیریت دقیق IPv6 و پورت
            if host_port.startswith('['):
                # فرمت: [ipv6]:port
                match = re.match(r'\[(.*?)\]:(\d+)', host_port)
                if match:
                    address, port = match.group(1), match.group(2)
                else:
                    return None, None, None
            else:
                # فرمت: ipv4:port یا domain:port
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

def test_connection(address, port, protocol='tcp', timeout=3):
    """تست اتصال TCP یا UDP به سرور و محاسبه زمان پاسخ"""
    start_time = time.perf_counter()
    try:
        if protocol == 'tcp':
            # تست دست‌تکانی سه مرحله‌ای TCP
            with socket.create_connection((address, port), timeout=timeout):
                rtt = int((time.perf_counter() - start_time) * 1000)
                return True, rtt
                
        elif protocol == 'udp':
            # پینگ واقعی UDP در لایه ترانسپورت بدون پاسخ سرور ناممکن است.
            # بهترین تقریب بدون مصرف دیتای زیاد، بررسی باز بودن سوکت محلی و عدم دریافت فوری ICMP Connection Refused است.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.connect((address, port))
                s.send(b'\x00')
                try:
                    # اگر سرور زنده نباشد و آی‌پی معتبر باشد، معمولاً پاسخی نمی‌آید (تایم اوت)
                    # اما اگر پورت بسته باشد، آی‌سی‌ام‌پي خطای Refused می‌دهد.
                    s.recv(1)
                except socket.timeout:
                    pass # در UDP تایم‌اوت لزوماً نشانه خرابی نیست
                except ConnectionRefusedError:
                    return False, None
                
                rtt = int((time.perf_counter() - start_time) * 1000)
                return True, rtt
                
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
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

def ping_configs(input_file='configs/proxy_configs.txt', output_file='configs/healthy_configs.txt', timeout=3, max_workers=100):
    """تابع اصلی: خواندن فایل، پینگ کردن و ذخیره کانفیگ‌های سالم"""
    logger.info(f"شروع پینگ‌گیر. در حال خواندن از {input_file}...")
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            configs = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"فایل ورودی {input_file} پیدا نشد.")
        return

    logger.info(f"تعداد {len(configs)} کانفیگ برای تست پیدا شد.")
    healthy_configs = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_config = {executor.submit(process_config, config, timeout): config for config in configs}
        
        for i, future in enumerate(concurrent.futures.as_completed(future_to_config)):
            config_str, is_alive, rtt = future.result()
            if is_alive:
                healthy_configs.append((config_str, rtt))
            
            if (i + 1) % 100 == 0 or (i + 1) == len(configs):
                logger.info(f"پیشرفت: {i + 1}/{len(configs)} تست شد. کانفیگ‌های سالم تا اینجا: {len(healthy_configs)}")

    # مرتب‌سازی کانفیگ‌ها بر اساس کمترین پینگ (RTT)
    healthy_configs.sort(key=lambda x: x[1] if x[1] is not None else 9999)

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for config, rtt in healthy_configs:
                f.write(config + '\n')
        logger.info(f"✅ با موفقیت {len(healthy_configs)} کانفیگ سالم (مرتب شده بر اساس پینگ) در فایل {output_file} ذخیره شد.")
    except Exception as e:
        logger.error(f"خطا در نوشتن فایل {output_file}: {e}")

if __name__ == "__main__":
    # اجرای ماژول
    ping_configs(timeout=3, max_workers=100)
