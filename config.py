import os
from dotenv import load_dotenv

load_dotenv()

# Supabase 設定
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')

# SurveyCake Webhook 配置
SURVEYCAKE_HASH_KEY = os.getenv('SURVEYCAKE_HASH_KEY', 'af1772c44d024d29')
SURVEYCAKE_IV_KEY = os.getenv('SURVEYCAKE_IV_KEY', '413bcfb9ca204f07')
SURVEYCAKE_DOMAIN = os.getenv('SURVEYCAKE_DOMAIN', 'sltung.surveycake.biz')
API_VERSION = os.getenv('API_VERSION', 'v0')

# API 設定
API_TIMEOUT = 10
MAX_RETRIES = 3
RETRY_DELAY = 2