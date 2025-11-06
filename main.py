from fastapi import FastAPI, HTTPException, Depends, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from bs4 import BeautifulSoup
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
import cloudscraper
import time
import random
import requests
import hashlib
import hmac
import base64
import json
import os
import jwt
import secrets
import logging

# ログ設定
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="ハーメルン読書データAPI",
    version="3.0.0",
    description="Render対応版 - セキュアな読書データ取得API"
)

# CORS設定
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# 環境変数から設定を読み込み
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "30"))
API_KEY = os.getenv("API_KEY", None)

# セキュリティスキーム
security = HTTPBearer()
basic_auth = HTTPBasic()

# データモデル
class LoginCredentials(BaseModel):
    user_id: str = Field(..., min_length=1, description="ハーメルンのユーザーID")
    password: str = Field(..., min_length=1, description="ハーメルンのパスワード")

class TokenRequest(BaseModel):
    credentials: LoginCredentials
    api_key: Optional[str] = Field(None, description="APIキー（設定されている場合は必須）")

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class ReadingData(BaseModel):
    year: int
    month: int
    book_count: int
    chapter_count: int
    word_count: int
    daily_data: Dict[int, Dict[str, int]]

class ReadingDataResponse(BaseModel):
    data: List[ReadingData]
    fetched_at: str
    cache_info: Optional[Dict[str, str]] = None

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    version: str

# ユーティリティ関数
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """JWTアクセストークンを生成"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": secrets.token_urlsafe(16)
    })
    
    # PyJWTを使用してエンコード
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)) -> dict:
    """トークンを検証"""
    token = credentials.credentials
    
    try:
        # PyJWTを使用してデコード
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="無効なトークンです",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="トークンの有効期限が切れています",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="トークンの検証に失敗しました",
            headers={"WWW-Authenticate": "Bearer"},
        )

def encrypt_credentials(user_id: str, password: str) -> str:
    """ログイン情報を暗号化"""
    data = json.dumps({"user_id": user_id, "password": password})
    # BASE64エンコード
    encoded = base64.b64encode(data.encode()).decode()
    # HMAC署名を追加
    signature = hmac.new(
        SECRET_KEY.encode(),
        encoded.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{encoded}.{signature}"

def decrypt_credentials(encrypted_data: str) -> Tuple[str, str]:
    """ログイン情報を復号化"""
    try:
        encoded, signature = encrypted_data.split(".")
        # 署名を検証
        expected_signature = hmac.new(
            SECRET_KEY.encode(),
            encoded.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("署名が無効です")
        
        # デコード
        data = json.loads(base64.b64decode(encoded).decode())
        return data["user_id"], data["password"]
    except Exception as e:
        logger.error(f"認証情報の復号化に失敗: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="認証情報の処理に失敗しました"
        )

def get_random_user_agent() -> str:
    """ランダムなUser-Agentを生成"""
    windows_versions = ["10.0", "11.0"]
    chrome_version = random.randint(119, 129)
    return (
        f"Mozilla/5.0 (Windows NT {random.choice(windows_versions)}; Win64; x64) "
        f"AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{chrome_version}.0.0.0 Safari/537.36"
    )

def get_random_delay() -> float:
    """ランダムな遅延を生成"""
    return random.uniform(1.0, 3.0)

def parse_count(text: str) -> int:
    """テキストから数値を抽出"""
    return int(text.replace("\n", "").replace(" ", "").replace("\t", "").replace(",", "").replace("-", "0"))

def parse_daily_data(daily_table) -> Dict[int, Dict[str, int]]:
    """日次データをパース"""
    daily_data = {}
    for row in daily_table:
        cells = row.find_all('td')
        if len(cells) < 4:
            continue
        try:
            day_text = cells[0].text.strip()
            # 日付を抽出（最後の2文字を取得）
            if len(day_text) >= 2:
                day = int(day_text[-2:].replace("日", ""))
                daily_data[day] = {
                    'daily_book_count': parse_count(cells[1].text),
                    'daily_chapter_count': parse_count(cells[2].text),
                    'daily_word_count': parse_count(cells[3].text)
                }
        except (ValueError, IndexError) as e:
            logger.warning(f"日次データのパースエラー: {e}")
            continue
    return daily_data

# キャッシュ用のデータ構造
class SimpleCache:
    def __init__(self, ttl_seconds: int = 300):
        self.cache = {}
        self.ttl = ttl_seconds
    
    def get(self, key: str) -> Optional[dict]:
        if key in self.cache:
            data, timestamp = self.cache[key]
            if datetime.utcnow().timestamp() - timestamp < self.ttl:
                return data
            else:
                del self.cache[key]
        return None
    
    def set(self, key: str, value: dict):
        self.cache[key] = (value, datetime.utcnow().timestamp())
    
    def clear(self):
        self.cache.clear()

# キャッシュインスタンス
data_cache = SimpleCache(ttl_seconds=300)

# ハーメルンクライアント
class HamelnClient:
    
    def __init__(self):
        self.scraper = None
        self.cookies = None
        self.user_id = None
    
    def login(self, user_id: str, password: str) -> bool:
        """ハーメルンにログイン"""
        try:
            self.scraper = cloudscraper.create_scraper(
                browser={
                    'browser': 'chrome',
                    'platform': 'windows',
                    'desktop': True
                }
            )
        except Exception as e:
            logger.error(f"CloudScraperの初期化エラー: {e}")
            # フォールバック: 基本的なCloudScraperを使用
            self.scraper = cloudscraper.create_scraper()
        
        headers = {
            "User-Agent": get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ja-JP,ja;q=0.9",
            "Referer": "https://syosetu.org/",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1"
        }
        
        login_url = "https://syosetu.org/?mode=login_entry"
        login_data = {
            "id": user_id,
            "pass": password,
            "autologin": "1",
            "submit": "ログイン",
            "mode": "login_entry_end",
            "redirect_mode": ""
        }
        
        try:
            response = self.scraper.post(login_url, headers=headers, data=login_data)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, "html.parser")

            print(soup)
            
            if "ログインに失敗しました" in response.text:
                logger.warning(f"ログイン失敗（明示的エラー）: user_id={user_id}")
                return False
            
            login_status = soup.find("ul", class_="spotlight")
            if login_status and "ログイン中" in login_status.get_text():
                logger.info(f"ログイン成功（ログイン中表示確認）: user_id={user_id}")
                self.cookies = self.scraper.cookies.get_dict()
                self.user_id = user_id
                return True
            
            user_links = soup.find_all("a", href=lambda x: x and "/user/" in x)
            if user_links:
                logger.info(f"ログイン成功（ユーザーリンク確認）: user_id={user_id}")
                self.cookies = self.scraper.cookies.get_dict()
                self.user_id = user_id
                return True
            
            cookies = self.scraper.cookies.get_dict()
            if cookies and any(key in cookies for key in ['SES2', 'sson', 'autologin']):
                logger.info(f"ログイン成功（セッションクッキー確認）: user_id={user_id}")
                self.cookies = cookies
                self.user_id = user_id
                return True
            
            login_form = soup.find("form", {"action": lambda x: x and "login" in str(x).lower()})
            if not login_form:
                if cookies:
                    logger.info(f"ログイン成功（ログインフォームなし）: user_id={user_id}")
                    self.cookies = cookies
                    self.user_id = user_id
                    return True
            
            logger.debug(f"ログイン後のHTML冒頭500文字: {response.text[:500]}")
            logger.debug(f"取得したクッキー: {cookies}")
            
            logger.warning(f"ログイン失敗（確認できず）: user_id={user_id}")
            return False
            
        except Exception as e:
            logger.error(f"ログインエラー: {e}")
            return False
    
    def verify_session(self) -> bool:
        if not self.scraper or not self.cookies:
            return False
        
        try:
            response = self.scraper.get("https://syosetu.org/")
            soup = BeautifulSoup(response.text, "html.parser")
            
            login_status = soup.find("ul", class_="spotlight")
            if login_status and "ログイン中" in login_status.get_text():
                return True
            
            return False
        except Exception as e:
            logger.error(f"セッション確認エラー: {e}")
            return False
    
    def fetch_reading_data(
        self, 
        year_from: Optional[int] = None, 
        year_to: Optional[int] = None
    ) -> List[ReadingData]:
        if not self.scraper or not self.cookies:
            raise ValueError("ログインが必要です")
        
        headers = {
            "User-Agent": get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ja-JP,ja;q=0.9",
            "Referer": "https://syosetu.org/",
            "DNT": "1"
        }
        
        reading_data = []
        current_year = datetime.now().year
        current_month = datetime.now().month
        
        STATS_START_YEAR = 2024
        STATS_START_MONTH = 2
        
        start_year = year_from if year_from else STATS_START_YEAR
        end_year = year_to if year_to else current_year
        
        if start_year < STATS_START_YEAR:
            logger.warning(f"開始年を{STATS_START_YEAR}年に修正しました")
            start_year = STATS_START_YEAR
        
        for year in range(start_year, end_year + 1):
            if year == STATS_START_YEAR:
                start_month = STATS_START_MONTH
            else:
                start_month = 1
            
            if year == current_year:
                end_month = current_month
            else:
                end_month = 12
            
            for month in range(start_month, end_month + 1):
                history_url = f"https://syosetu.org/?mode=view_reading_history&type=&date={year}-{month:02d}"
                
                try:
                    response = self.scraper.get(history_url, headers=headers)
                    response.raise_for_status()
                    
                    soup = BeautifulSoup(response.text, "html.parser")
                    
                    login_form = soup.find("form", {"action": lambda x: x and "login" in str(x).lower()})
                    if login_form:
                        logger.error("セッションが無効です（ログインフォーム検出）")
                        raise ValueError("セッションが無効です")
                    
                    if "ログインしてください" in response.text:
                        logger.error("セッションが無効です（ログイン要求検出）")
                        raise ValueError("セッションが無効です")
                    
                    table = soup.find('table', class_="table1")
                    
                    if not table:
                        logger.info(f"{year}-{month:02d}のデータなし")
                        continue
                    
                    info = table.find_all("td")
                    if len(info) < 3:
                        continue
                    
                    book_count = parse_count(info[0].get_text())
                    chapter_count = parse_count(info[1].get_text())
                    word_count = parse_count(info[2].get_text())
                    
                    daily_data = {}
                    daily_tables = soup.find_all('table', class_='table1')
                    if len(daily_tables) >= 4:
                        daily_rows = daily_tables[3].find_all('tr')[1:-1]
                        daily_data = parse_daily_data(daily_rows)
                    
                    reading_data.append(ReadingData(
                        year=year,
                        month=month,
                        book_count=book_count,
                        chapter_count=chapter_count,
                        word_count=word_count,
                        daily_data=daily_data
                    ))
                    
                    logger.info(f"{year}-{month:02d}のデータ取得成功")
                    time.sleep(get_random_delay())
                    
                except Exception as e:
                    logger.warning(f"{year}-{month:02d}のデータ取得エラー: {e}")
                    continue
            
            # 年ごとの遅延
            if year < end_year:
                time.sleep(get_random_delay())
        
        return reading_data

# エンドポイント
@app.get("/", response_model=dict)
async def root():
    """APIのルート情報"""
    return {
        "name": "ハーメルン読書データAPI",
        "version": "3.0.0",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "token": "/api/v3/token",
            "reading_data": "/api/v3/reading-data",
            "reading_data_basic": "/api/v3/reading-data/basic",
            "documentation": "/docs"
        },
        "deployment": "Render",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """ヘルスチェックエンドポイント（Render用）"""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.utcnow().isoformat(),
        version="3.0.0"
    )

@app.post("/api/v3/token", response_model=TokenResponse)
async def create_token(request: TokenRequest):
    """
    認証トークンを生成
    ログイン情報を暗号化してトークンに含める
    """
    # APIキーの検証（設定されている場合）
    if API_KEY and request.api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="無効なAPIキーです"
        )
    
    # ログイン情報を検証（実際にログインを試みる）
    client = HamelnClient()
    if not client.login(request.credentials.user_id, request.credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ハーメルンへのログインに失敗しました。IDまたはパスワードを確認してください。"
        )
    
    # ログイン情報を暗号化
    encrypted_creds = encrypt_credentials(
        request.credentials.user_id,
        request.credentials.password
    )
    
    # トークンを生成
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": request.credentials.user_id, "creds": encrypted_creds},
        expires_delta=access_token_expires
    )
    
    logger.info(f"トークン発行: user_id={request.credentials.user_id}")
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

@app.get("/api/v3/reading-data", response_model=ReadingDataResponse)
async def get_reading_data(
    year_from: Optional[int] = None,
    year_to: Optional[int] = None,
    use_cache: bool = True,
    token_data: dict = Depends(verify_token)
):
    """
    読書データを取得
    トークンからログイン情報を復元してハーメルンにアクセス
    """
    # キャッシュキーを生成
    cache_key = f"{token_data['sub']}:{year_from}:{year_to}"
    
    # キャッシュを確認
    if use_cache:
        cached_data = data_cache.get(cache_key)
        if cached_data:
            logger.info(f"キャッシュヒット: {cache_key}")
            return ReadingDataResponse(
                data=cached_data["data"],
                fetched_at=cached_data["fetched_at"],
                cache_info={"cached": "true", "cached_at": cached_data["fetched_at"]}
            )
    
    # トークンからログイン情報を復元
    encrypted_creds = token_data.get("creds")
    if not encrypted_creds:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="トークンに認証情報が含まれていません"
        )
    
    user_id, password = decrypt_credentials(encrypted_creds)
    
    # ハーメルンにログインしてデータを取得
    client = HamelnClient()
    if not client.login(user_id, password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ハーメルンへの再ログインに失敗しました"
        )
    
    try:
        reading_data = client.fetch_reading_data(year_from, year_to)
        
        # レスポンスデータを作成
        response_data = {
            "data": reading_data,
            "fetched_at": datetime.utcnow().isoformat()
        }
        
        # キャッシュに保存
        if use_cache:
            data_cache.set(cache_key, response_data)
            logger.info(f"キャッシュ保存: {cache_key}")
        
        return ReadingDataResponse(
            data=reading_data,
            fetched_at=response_data["fetched_at"],
            cache_info={"cached": "false"}
        )
        
    except Exception as e:
        logger.error(f"データ取得エラー: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"データの取得に失敗しました: {str(e)}"
        )

@app.post("/api/v3/reading-data/basic", response_model=ReadingDataResponse)
async def get_reading_data_basic(
    credentials: HTTPBasicCredentials = Depends(basic_auth),
    year_from: Optional[int] = None,
    year_to: Optional[int] = None
):
    """
    Basic認証で直接読書データを取得（シンプルな使用方法）
    """
    logger.info(f"Basic認証アクセス: user_id={credentials.username}")
    
    # ハーメルンにログインしてデータを取得
    client = HamelnClient()
    if not client.login(credentials.username, credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ログインに失敗しました",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    try:
        reading_data = client.fetch_reading_data(year_from, year_to)
        
        return ReadingDataResponse(
            data=reading_data,
            fetched_at=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"データ取得エラー: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"データの取得に失敗しました: {str(e)}"
        )

# エラーハンドラー
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.status_code,
                "message": exc.detail
            },
            "timestamp": datetime.utcnow().isoformat()
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"予期しないエラー: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": 500,
                "message": "内部サーバーエラーが発生しました"
            },
            "timestamp": datetime.utcnow().isoformat()
        }
    )

# 起動時のログ
@app.on_event("startup")
async def startup_event():
    logger.info("ハーメルン読書データAPI v3.0.0 起動")
    logger.info(f"環境: SECRET_KEY設定={bool(SECRET_KEY)}, API_KEY設定={bool(API_KEY)}")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("APIを終了します")
