from flask import Flask, request, jsonify
from supabase import create_client, Client
from Crypto.Cipher import AES
import base64
import json
import requests
import time
import logging
from datetime import datetime
from config import *

# 設定日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# 初始化 Supabase
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


# ============================================
# 工具函數
# ============================================

def extract_first_json(text):
    """從字串中擷取第一個完整的 JSON 物件"""
    brace_count = 0
    json_end = -1
    for i, char in enumerate(text):
        if char == '{':
            brace_count += 1
        elif char == '}':
            brace_count -= 1
            if brace_count == 0:
                json_end = i + 1
                break
    if json_end > 0:
        return text[:json_end]
    return None


def fetch_surveycake_data(svid, hash_value):
    """從 SurveyCake API 取得加密資料"""
    api_url = f"https://{SURVEYCAKE_DOMAIN}/webhook/{API_VERSION}/{svid}/{hash_value}"

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info(f"[{attempt}/{MAX_RETRIES}] 正在從 SurveyCake API 取得資料...")
            response = requests.get(api_url, timeout=API_TIMEOUT)
            logger.info(f"API 回應狀態碼: {response.status_code}")

            if response.status_code != 200:
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY)
                continue

            # 檢查是否為錯誤訊息
            try:
                json_response = json.loads(response.text)
                if isinstance(json_response, dict) and json_response.get('status') == False:
                    error_msg = json_response.get('message', '未知錯誤')
                    logger.error(f"❌ SurveyCake API 回傳錯誤: {error_msg}")
                    if "not exist" in error_msg and attempt < MAX_RETRIES:
                        time.sleep(RETRY_DELAY)
                        continue
                    return None
            except json.JSONDecodeError:
                pass

            # 驗證 Base64 格式
            encrypted_data = response.text.strip()
            try:
                test_decode = base64.b64decode(encrypted_data)
                if len(test_decode) % 16 != 0:
                    if attempt < MAX_RETRIES:
                        time.sleep(RETRY_DELAY)
                        continue
                    return None
                logger.info(f"✓ 成功取得有效的加密資料")
                return encrypted_data
            except Exception as e:
                logger.error(f"❌ Base64 驗證失敗: {e}")
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY)
                continue

        except Exception as e:
            logger.error(f"❌ 請求錯誤: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
            continue

    logger.error(f"❌ 已達到最大重試次數 ({MAX_RETRIES})")
    return None


def get_survey_keys(svid):
    """從 Supabase 查詢問卷的密鑰配置"""
    try:
        logger.info(f"正在查詢問卷 {svid} 的密鑰配置...")
        result = supabase.table('survey_keys').select('hash_key, iv_key, survey_name').eq('survey_id', svid).eq('is_active', True).execute()

        if result.data and len(result.data) > 0:
            keys = result.data[0]
            logger.info(f"✓ 找到問卷密鑰配置: {keys.get('survey_name', svid)}")
            return keys['hash_key'], keys['iv_key']
        else:
            logger.error(f"❌ 找不到問卷 {svid} 的密鑰配置")
            return None, None
    except Exception as e:
        logger.error(f"❌ 查詢密鑰配置錯誤: {e}")
        import traceback
        traceback.print_exc()
        return None, None


def decrypt_surveycake_data(encrypted_data, hash_key, iv_key):
    """解密 SurveyCake webhook 資料"""
    try:
        encrypted_bytes = base64.b64decode(encrypted_data)
        key = hash_key.encode('utf-8')
        iv = iv_key.encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_bytes)
        decrypted_data = decrypted_padded.rstrip(b'\0')
        decrypted_str = decrypted_data.decode('utf-8').strip()

        try:
            decrypted_json = json.loads(decrypted_str)
        except json.JSONDecodeError as je:
            logger.warning(f"⚠️ JSON 解析失敗，嘗試擷取第一個完整的 JSON: {je}")
            json_str = extract_first_json(decrypted_str)
            if json_str:
                decrypted_json = json.loads(json_str)
            else:
                raise

        logger.info(f"✓ 解密成功")
        return decrypted_json
    except Exception as e:
        logger.error(f"❌ 解密錯誤: {e}")
        import traceback
        traceback.print_exc()
        return None


def insert_to_supabase(data, svid, hash_value):
    """插入問卷回應資料到 Supabase"""
    try:
        survey_hash = svid
        survey_name = data.get('title', '')
        response_hash = hash_value
        respondent_id = str(data.get('mbrid', ''))

        submit_time_str = data.get('submitTime', '')
        try:
            submit_time = datetime.strptime(submit_time_str, '%Y-%m-%d %H:%M:%S').isoformat()
        except:
            submit_time = datetime.now().isoformat()

        # 準備資料
        record = {
            'survey_hash': survey_hash,
            'survey_name': survey_name,
            'response_hash': response_hash,
            'respondent_id': respondent_id,
            'submit_time': submit_time,
            'response_data': data
        }

        # 使用 upsert 處理重複資料（基於 response_hash 的 UNIQUE 約束）
        result = supabase.table('survey_responses').upsert(
            record,
            on_conflict='response_hash'
        ).execute()

        logger.info(f"✓ 成功儲存到 Supabase，Response Hash: {response_hash}")
        return True

    except Exception as e:
        logger.error(f"❌ 儲存到 Supabase 錯誤: {e}")
        import traceback
        traceback.print_exc()
        return False


# ============================================
# Flask 路由
# ============================================

@app.route('/', methods=['GET'])
def home():
    """首頁"""
    return jsonify({
        'status': 'running',
        'service': 'SurveyCake Webhook Receiver',
        'version': '2.0',
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/health', methods=['GET'])
def health():
    """健康檢查"""
    try:
        # 測試 Supabase 連線
        supabase.table('survey_responses').select('id').limit(1).execute()
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500


@app.route('/webhook/surveycake', methods=['POST'])
def surveycake_webhook():
    """接收 SurveyCake webhook 通知"""
    try:
        logger.info("=" * 60)
        logger.info("收到 SurveyCake Webhook 請求")
        logger.info("=" * 60)

        # 記錄來源 IP
        x_forwarded_for = request.headers.get('X-Forwarded-For')
        if x_forwarded_for:
            client_ip = x_forwarded_for.split(',')[0].strip()
        else:
            client_ip = request.remote_addr

        logger.info(f"🌐 來源 IP: {client_ip}")
        logger.info(f"   Remote Addr: {request.remote_addr}")
        logger.info(f"   X-Forwarded-For: {request.headers.get('X-Forwarded-For')}")
        logger.info(f"   X-Real-IP: {request.headers.get('X-Real-IP')}")
        logger.info(f"   User-Agent: {request.headers.get('User-Agent')}")
        logger.info("-" * 60)

        # 驗證請求格式
        if 'application/x-www-form-urlencoded' not in (request.content_type or '') and not request.form:
            return jsonify({
                'status': 'error',
                'message': '不支援的請求格式'
            }), 400

        # 取得參數
        form_data = request.form.to_dict()
        svid = form_data.get('svid')
        hash_value = form_data.get('hash')

        if not svid or not hash_value:
            return jsonify({
                'status': 'error',
                'message': '缺少必要的參數 (svid 或 hash)'
            }), 400

        logger.info(f"問卷 ID (svid): {svid}")
        logger.info(f"回應 Hash: {hash_value}")

        # 步驟 1: 查詢問卷的密鑰配置
        hash_key, iv_key = get_survey_keys(svid)
        if hash_key is None or iv_key is None:
            return jsonify({
                'status': 'error',
                'message': f'找不到問卷 {svid} 的密鑰配置，請先在 Supabase 的 survey_keys 表格中新增此問卷的密鑰'
            }), 404

        # 步驟 2: 從 SurveyCake API 取得加密資料
        encrypted_data = fetch_surveycake_data(svid, hash_value)
        if encrypted_data is None:
            return jsonify({
                'status': 'error',
                'message': '無法從 SurveyCake API 取得資料'
            }), 500

        # 步驟 3: 解密資料
        logger.info("正在解密資料...")
        decrypted_data = decrypt_surveycake_data(encrypted_data, hash_key, iv_key)
        if decrypted_data is None:
            return jsonify({
                'status': 'error',
                'message': '解密失敗'
            }), 500

        logger.info(f"問卷標題: {decrypted_data.get('title', 'N/A')}")
        logger.info(f"提交時間: {decrypted_data.get('submitTime', 'N/A')}")
        logger.info(f"回應數量: {len(decrypted_data.get('result', []))}")

        # 步驟 4: 儲存到 Supabase
        logger.info("正在儲存到 Supabase...")
        success = insert_to_supabase(decrypted_data, svid, hash_value)

        if success:
            logger.info("✓ 處理完成！")
            return jsonify({
                'status': 'success',
                'message': '資料已成功儲存到 Supabase'
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': '資料儲存失敗'
            }), 500

    except Exception as e:
        logger.error(f"❌ 處理 webhook 錯誤: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)