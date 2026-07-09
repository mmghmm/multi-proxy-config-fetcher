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

def parse_config(config_str):
    """استخراج پروتکل، آدرس و پورت از رشته کانفیگ"""
    config_str = config_str.strip()
    if not config_str:
        return None, None, None

    try:
        if config_str.startswith('vmess://'):
            # فرمت VMess: vmess://base64_json
            json_str = base64.b64decode(config_str[8:]).decode('utf-8')
            data = json.loads(json_str)
            return 'tcp', data.get('add'), int(data.get('port'))
            
        elif config_str.startswith(('vless://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://', 'tuic://')):
            # فرمت سایر پروتکل‌ها: protocol://uuid@address:port?...
            parsed = urlparse(config_str)
            host_port = parsed.netloc.split('@')[-1]
            if ':' in host_port:
                address, port = host_port.rsplit(':', 1)
                port = port.split('?')[0] # حذف پارامترهای اضافی از پورت
                # پروتکل‌های مبتنی بر QUIC از UDP استفاده می‌کنند
                protocol = 'udp' if config_str.startswith(('hysteria2://', 'hy2://', 'tuic://')) else 'tcp'
                return protocol, address, int(port)
                
        elif config_str.startswith('wireguard://'):
            # WireGuard ساختار پیچیده‌ای دارد و معمولاً نیاز به تنظیمات سطح سیستم دارد
            # برای سادگی، آن را رد می‌کنیم
            return None, None, None

    except Exception as e:
        logger.warning(f"خطا در پارس کانفیگ: {config_str[:30]}... | خطا: {e}")
        
    return None, None, None

def test_connection(address, port, protocol='tcp', timeout=3):
    """تست اتصال TCP یا UDP به سرور"""
    try:
        if protocol == 'tcp':
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((address, port))
                return True
                
        elif protocol == 'udp':
            # برای UDP (مخصوص QUIC)، فقط چک می‌کنیم که روتینگ مشکل ندارد
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.connect((address, port))
                s.send(b'\x00') # ارسال یک پکت کوچک
                try:
                    s.recv(1)
                except socket.timeout:
                    # تایم‌اوت در UDP یعنی پکت رفت ولی جوابی نیامد (که برای QUIC طبیعی است)
                    return True 
                except ConnectionRefusedError:
                    return False
                return True
                
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        return False
    except Exception as e:
        logger.error(f"خطای غیرمنتظره در تست {address}:{port} - {e}")
        return False

def process_config(config_str, timeout):
    """پردازش یک کانفیگ: پارس و تست اتصال"""
    protocol, address, port = parse_config(config_str)
    if not address or not port:
        return config_str, False # اگر پارس نشد، رد می‌کنیم
    
    is_alive = test_connection(address, port, protocol, timeout)
    return config_str, is_alive

def ping_configs(input_file='configs/proxy_configs.txt', output_file='configs/healthy_configs.txt', timeout=3, max_workers=50):
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
    
    # استفاده از ThreadPoolExecutor برای تست همزمان (بسیار سریع)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_config = {executor.submit(process_config, config, timeout): config for config in configs}
        
        for i, future in enumerate(concurrent.futures.as_completed(future_to_config)):
            config_str, is_alive = future.result()
            if is_alive:
                healthy_configs.append(config_str)
            
            # نمایش پیشرفت هر ۱۰۰ کانفیگ
            if (i + 1) % 100 == 0 or (i + 1) == len(configs):
                logger.info(f"پیشرفت: {i + 1}/{len(configs)} تست شد. کانفیگ‌های سالم تا اینجا: {len(healthy_configs)}")

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for config in healthy_configs:
                f.write(config + '\n')
        logger.info(f"✅ با موفقیت {len(healthy_configs)} کانفیگ سالم در فایل {output_file} ذخیره شد.")
    except Exception as e:
        logger.error(f"خطا در نوشتن فایل {output_file}: {e}")

if __name__ == "__main__":
    # اجرای ماژول
    # timeout: زمان انتظار برای هر سرور (به ثانیه). برای شبکه‌های کندتر می‌توانید ۵ بگذارید.
    # max_workers: تعداد تست‌های همزمان. اگر سیستم‌تان قوی است می‌توانید تا ۲۰۰ هم بالا ببرید.
    ping_configs(timeout=3, max_workers=100)
