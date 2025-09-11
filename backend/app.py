"""
Flask backend for the shop application.

This is a minimal API server implementing user registration, login and
product/point endpoints. It is designed to run inside a container on
Kubernetes/EKS. Secrets such as the database URI and JWT secret
are injected via environment variables.

For a real application you would expand these endpoints, add proper
error handling, authentication (e.g. JWT), and input validation.
"""

from datetime import datetime, timedelta
import os
import json
import logging
import redis

# 테스트 환경용 .env 파일 로드1
from dotenv import load_dotenv
if os.path.exists('.env.test'):
    load_dotenv('.env.test')

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask application instance
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///shop.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.environ.get('JWT_SECRET_KEY', 'change-me'))
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'change-me')

# Redis 완전 비활성화
# Redis 클라이언트 설정
redis_client = None  # 기본값

# Redis 연결 함수
def init_redis():
    global redis_client
    try:
        if os.environ.get('REDIS_HOST'):
            redis_client = redis.Redis(
                host=os.environ.get('REDIS_HOST'),
                port=int(os.environ.get('REDIS_PORT', 6379)),
                decode_responses=True,
                ssl=True,
                ssl_cert_reqs=None,
                ssl_check_hostname=False,
                socket_timeout=3,
                socket_connect_timeout=3
            )
            redis_client.ping()
            logger.info("Redis connection established successfully")
        else:
            logger.info("No Redis host configured")
    except Exception as e:
        logger.warning(f"Redis connection failed: {str(e)}")
        redis_client = None

# Redis 초기화 시도
try:
    init_redis()
except:
    pass  # Redis 실패해도 앱은 계속 실행

db = SQLAlchemy(app)
CORS(app)


class User(db.Model):
    """User account model.

    Fields:
    - id: primary key
    - email: unique user identifier
    - password_hash: hashed password
    - name: display name
    - phone: optional phone number
    - points_balance: integer points balance
    - created_at: registration timestamp
    """
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False) # Length Limit Changed @08/31
    name = db.Column(db.String(80), nullable=False)
    phone = db.Column(db.String(20))
    points_balance = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    point_transactions = db.relationship(
        "PointTransaction",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    def check_password(self, password: str) -> bool:
        """Verify a plaintext password against the stored hash."""
        return check_password_hash(self.password_hash, password)


class PointTransaction(db.Model):
    """Tracks changes to a user's point balance."""
    __tablename__ = 'point_transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    delta = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(255), nullable=False)
    note = db.Column(db.String(255))
    receipt_json = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship("User", back_populates="point_transactions")


class Product(db.Model):
    """Product catalog model."""
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    stock = db.Column(db.Integer, default=0, nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)


def init_db():
    """Initialize the database (create tables)."""
    with app.app_context():
        db.create_all()
        logger.info("Database tables created successfully")


# 1. 기존 root 함수 (122-125줄) 교체체
@app.route('/', methods=['GET'])
def root():
    """Root endpoint with Redis caching."""
    try:
        if redis_client:
            cached_info = redis_client.get('server_info')
            if cached_info:
                data = json.loads(cached_info)
                data['cache'] = 'hit'
                return jsonify(data), 200
        
        result = {
            'status': 'ok', 
            'service': 'shop-backend', 
            'version': '1.0.0',
            'cache': 'miss'
        }
        
        # Redis 사용 가능하면 5분간 캐시
        if redis_client:
            redis_client.setex('server_info', 300, json.dumps(result))
        
        return jsonify(result), 200
        
    except Exception as e:
        # Redis 실패해도 기본 응답
        return jsonify({'status': 'ok', 'service': 'shop-backend', 'version': '1.0.0'}), 200



@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register a new user.

    Expects JSON with `email`, `password` and `name`. Returns a success
    message or an error if the email already exists.
    """
    try:
        data = request.get_json() or {}
        email = data.get('email', '').strip().lower()
        password = data.get('password', '').strip()
        name = data.get('name', '').strip()
        phone = data.get('phone', '').strip()

        logger.info(f"=== REGISTER DEBUG ===")
        logger.info(f"Email: '{email}', Password: '{password}', Name: '{name}'")

        # Input validation
        if not email or not password or not name:
            return jsonify({'error': 'Email, password and name are required'}), 400

        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400

        # Check if user exists
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 409

        password_hash = generate_password_hash(password)
        logger.info(f"Generated hash: {password_hash}")
        
        user = User(email=email, password_hash=password_hash, name=name, phone=phone)
        db.session.add(user)
        db.session.commit()

        logger.info(f"New user registered: {email}")
        return jsonify({'message': 'User registered successfully', 'user_id': user.id}), 201

    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/auth/login', methods=['POST'])
def login():
    """Authenticate a user and return a dummy JWT.

    In a production environment you would issue a real JWT with expiry
    information. For simplicity this returns a static token.
    """
    try:
        data = request.get_json() or {}
        email = data.get('email', '').strip().lower()
        password = data.get('password', '').strip()
        
        # 디버깅 로그 추가
        logger.info(f"=== LOGIN DEBUG START ===")
        logger.info(f"Received data: {data}")
        logger.info(f"Email: '{email}', Password: '{password}', Password length: {len(password)}")
        
        if not email or not password:
            logger.info("Missing email or password")
            return jsonify({'error': 'Email and password are required'}), 400

        user = User.query.filter_by(email=email).first()
        logger.info(f"User found in DB: {user is not None}")
        
        if user:
            logger.info(f"User email in DB: '{user.email}'")
            logger.info(f"DB password hash: {user.password_hash}")
            logger.info(f"Attempting to check password: '{password}'")
            
            # 수동으로 해시 체크 과정 확인
            password_check = check_password_hash(user.password_hash, password)
            logger.info(f"Password check result: {password_check}")
            
            # 추가: 새로운 해시 생성해서 비교
            new_hash = generate_password_hash(password)
            logger.info(f"New hash for same password: {new_hash}")
        else:
            logger.info("No user found with this email")
        
        if not user or not user.check_password(password):
            logger.info(f"Authentication failed for email: '{email}'")
            return jsonify({'error': 'Invalid credentials'}), 401

        # Return a simple token (in real life generate JWT)
        token = f'dummy-token-{user.id}'
        logger.info(f"User logged in successfully: {email}")
        return jsonify({
            'token': token, 
            'user_id': user.id, 
            'name': user.name,
            'email': user.email,
            'points_balance': user.points_balance
        }), 200

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/account/points', methods=['GET'])
def get_points():
    """Return the point balance and transaction history for a user.

    In a real application, user identification would come from the JWT.
    Here we take a `user_id` query parameter for demonstration.
    """
    try:
        user_id = request.args.get('user_id', type=int)
        if not user_id:
            return jsonify({'error': 'Missing user_id parameter'}), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        transactions = [
            {
                'id': t.id,
                'delta': t.delta,
                'reason': t.reason,
                'note': t.note,
                'created_at': t.created_at.isoformat(),
            }
            for t in user.point_transactions
        ]

        return jsonify({
            'points': user.points_balance, 
            'transactions': transactions,
            'user_name': user.name
        }), 200

    except Exception as e:
        logger.error(f"Get points error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/products', methods=['GET'])
def list_products():
    """Return a list of all products."""
    try:
        products = Product.query.all()
        items = [
            {
                'id': p.id,
                'name': p.name,
                'stock': p.stock,
                'price': float(p.price),
            }
            for p in products
        ]
        return jsonify({'items': items, 'count': len(items)}), 200

    except Exception as e:
        logger.error(f"List products error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/products/<int:prod_id>', methods=['GET'])
def get_product(prod_id):
    """Return details for a single product."""
    try:
        product = Product.query.get(prod_id)
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        
        return jsonify({
            'id': product.id,
            'name': product.name,
            'stock': product.stock,
            'price': float(product.price),
        }), 200

    except Exception as e:
        logger.error(f"Get product error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


# 2. 기존 health 함수 (310-326줄) 교체  
@app.route('/api/health', methods=['GET'])
def health():
    """Simple health check endpoint with Redis caching."""
    try:
        # 캐시 확인 (30초 TTL)
        if redis_client:
            cached_health = redis_client.get('health_status')
            if cached_health:
                data = json.loads(cached_health)
                data['cache'] = 'hit'
                return jsonify(data), 200
        
        # DB 연결 테스트
        db.session.execute(db.text('SELECT 1'))
        db_status = 'ok'
        
        result = {
            'status': 'ok', 
            'service': 'shop-backend',
            'database': db_status,
            'timestamp': datetime.utcnow().isoformat(),
            'cache': 'miss'
        }
        
        # Redis 사용 가능하면 30초간 캐시
        if redis_client:
            redis_client.setex('health_status', 30, json.dumps(result))
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Health check error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# 3. 새로운 통계 엔드포인트 추가 (아무 곳에나)
@app.route('/api/stats', methods=['GET'])
def get_stats():
    """통계 엔드포인트 - Redis 카운터 연습용"""
    try:
        if not redis_client:
            return jsonify({'error': 'Redis not available'}), 503
            
        # 방문 카운터 증가
        visit_count = redis_client.incr('visit_count')
        
        # 오늘 날짜별 카운터
        today = datetime.utcnow().strftime('%Y-%m-%d')
        daily_count = redis_client.incr(f'daily_visits:{today}')
        redis_client.expire(f'daily_visits:{today}', 86400 * 7)  # 7일 보관
        
        return jsonify({
            'total_visits': visit_count,
            'today_visits': daily_count,
            'date': today,
            'redis_status': 'connected'
        }), 200
        
    except Exception as e:
        logger.error(f"Stats error: {str(e)}")
        return jsonify({'error': 'Stats unavailable'}), 500

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500


def init_demo_user():
    """시연용 데모 사용자 초기화"""
    try:
        demo_user = User.query.filter_by(email='demo@kolon.com').first()
        if not demo_user:
            demo_user = User(
                email='demo@kolon.com',
                password_hash=generate_password_hash('demo123'),
                name='Kolon 시연 계정',
                phone='010-0000-0000',
                points_balance=200000  # 충분한 초기 포인트
            )
            db.session.add(demo_user)
            db.session.commit()
            logger.info("Demo user created with 200,000 points")
        return demo_user
    except Exception as e:
        logger.error(f"Demo user init error: {str(e)}")
        return None

@app.route('/api/demo/points', methods=['GET'])
def get_demo_points():
    """시연용 포인트 잔액 조회"""
    try:
        demo_user = User.query.filter_by(email='demo@kolon.com').first()
        if not demo_user:
            demo_user = init_demo_user()
            
        if not demo_user:
            return jsonify({'error': 'Demo user creation failed'}), 500
            
        return jsonify({
            'points_balance': demo_user.points_balance,
            'user_name': demo_user.name
        }), 200
        
    except Exception as e:
        logger.error(f"Demo points balance error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/demo/points/add', methods=['POST'])
def add_demo_points():
    """시연용 포인트 충전 (50,000P 고정)"""
    try:
        demo_user = User.query.filter_by(email='demo@kolon.com').first()
        if not demo_user:
            demo_user = init_demo_user()
            
        if not demo_user:
            return jsonify({'error': 'Demo user not found'}), 404
        
        # 50,000 포인트 추가
        amount = 50000
        demo_user.points_balance += amount
        
        # 포인트 트랜잭션 기록
        transaction = PointTransaction(
            user_id=demo_user.id,
            delta=amount,
            reason="시연용 포인트 충전",
            note="데모 충전 버튼"
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        logger.info(f"Added {amount} points to demo user. New balance: {demo_user.points_balance}")
        
        return jsonify({
            'message': 'Points added successfully',
            'new_balance': demo_user.points_balance,
            'added_amount': amount
        }), 200
        
    except Exception as e:
        logger.error(f"Add demo points error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/demo/points/deduct', methods=['POST'])
def deduct_demo_points():
    """시연용 포인트 차감"""
    try:
        data = request.get_json()
        amount = int(data.get('amount', 0))
        
        if amount <= 0:
            return jsonify({'error': 'Invalid amount'}), 400
            
        demo_user = User.query.filter_by(email='demo@kolon.com').first()
        if not demo_user:
            return jsonify({'error': 'Demo user not found'}), 404
        
        if demo_user.points_balance < amount:
            return jsonify({'error': 'Insufficient points'}), 400
        
        # 포인트 차감
        demo_user.points_balance -= amount
        
        # 포인트 트랜잭션 기록
        transaction = PointTransaction(
            user_id=demo_user.id,
            delta=-amount,
            reason="결제에 사용",
            note="상품 결제"
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        logger.info(f"Deducted {amount} points from demo user. New balance: {demo_user.points_balance}")
        
        return jsonify({
            'message': 'Points deducted successfully',
            'new_balance': demo_user.points_balance,
            'deducted_amount': amount
        }), 200
        
    except Exception as e:
        logger.error(f"Deduct demo points error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

def init_db():
    """Initialize database tables and demo user"""
    try:
        with app.app_context():
            db.create_all()
            init_demo_user()  # 데모 사용자 초기화 추가
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")
        raise

if __name__ == '__main__':
    # Create DB tables when running locally (uses sqlite if no DB provided)
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
