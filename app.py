from flask import Flask, render_template, request, redirect, url_for, session, make_response
import requests
import urllib3
from datetime import datetime, timedelta
import logging
import os
from flask_wtf.csrf import CSRFProtect, generate_csrf # type: ignore
from flask_login import login_required, LoginManager, UserMixin, login_user, logout_user, current_user # type: ignore
from flask_compress import Compress # type: ignore
from functools import wraps

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = 'your-very-secret-key-here'  # Thay đổi secret key

# Cấu hình session
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)

@app.before_request
def before_request():
    session.permanent = True  # Set session to permanent
    if 'token' in session:
        logging.info(f"Token exists in session: {bool(session.get('token'))}")

# Enable compression
Compress(app)

# Cấu hình logging
logging.basicConfig(level=logging.INFO)

API_BASE = "https://sinhvien1.tlu.edu.vn/education"

csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # tên route login

# Cache configuration
CACHE_TIMEOUT = 1800  # 30 minutes

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    # Ở đây bạn có thể lấy user từ database, ví dụ:
    return User(user_id)

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logging.info("Checking token in session...")
        logging.info(f"Current session data: {dict(session)}")
        if 'token' not in session:
            logging.error("Token not found in session")
            return redirect(url_for('login', next=request.url))
        if not session['token']:
            logging.error("Token is empty")
            return redirect(url_for('login', next=request.url))
        logging.info("Token found in session, proceeding...")
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logging.error(f"Error in protected route: {str(e)}")
            return redirect(url_for('login'))
    return decorated_function

def get_cached_data(session_key, expiry_key):
    now = datetime.utcnow()
    cached_data = session.get(session_key)
    expiry_str = session.get(expiry_key)
    
    if cached_data and expiry_str:
        expiry = datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%S")
        if now < expiry:
            return cached_data
    return None

def set_cached_data(session_key, expiry_key, data):
    session[session_key] = data
    session[expiry_key] = (datetime.utcnow() + timedelta(seconds=CACHE_TIMEOUT)).strftime("%Y-%m-%dT%H:%M:%S")

def api_post(endpoint, data, token=None, timeout=10):
    headers = {
        "Authorization": f"Bearer {token}" if token else "",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive"
    }
    url = f"{API_BASE}{endpoint}"
    try:
        resp = requests.post(url, data=data, headers=headers, verify=False, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.Timeout:
        raise Exception("Kết nối đến máy chủ bị timeout. Vui lòng thử lại sau.")
    except requests.exceptions.ConnectionError:
        raise Exception("Không thể kết nối đến máy chủ. Vui lòng kiểm tra kết nối internet của bạn.")
    except requests.exceptions.RequestException as e:
        raise Exception(f"Lỗi kết nối: {str(e)}")

def api_get(endpoint, token=None, timeout=10):
    headers = {
        "Authorization": f"Bearer {token}" if token else "",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive"
    }
    url = f"{API_BASE}{endpoint}"
    try:
        resp = requests.get(url, headers=headers, verify=False, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.Timeout:
        raise Exception("Kết nối đến máy chủ bị timeout. Vui lòng thử lại sau.")
    except requests.exceptions.ConnectionError:
        raise Exception("Không thể kết nối đến máy chủ. Vui lòng kiểm tra kết nối internet của bạn.")
    except requests.exceptions.RequestException as e:
        raise Exception(f"Lỗi kết nối: {str(e)}")

@app.route('/', methods=['GET', 'POST'])
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    logging.info(f"Login route - Method: {request.method}")
    logging.info(f"Current session data: {dict(session)}")
    
    if request.method == 'GET':
        # Only clear session if explicitly logging out
        if request.args.get('logout'):
            logging.info("Logout parameter detected, clearing session")
            session.clear()
            return redirect(url_for('login'))
            
        # If user is already logged in, redirect to schedule
        if 'token' in session and session['token']:
            logging.info("User already logged in, redirecting to schedule")
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('schedule'))
            
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        login_data = {
            "client_id": "education_client",
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_secret": "password"
        }
        try:
            logging.info("Attempting to login with API")
            resp = api_post("/oauth/token", login_data)
            token = resp["access_token"]
            logging.info("Login successful, setting session data")
            
            # Set session data
            session.permanent = True
            session['username'] = username
            session['token'] = token
            session.modified = True
            
            logging.info(f"Session after login: {dict(session)}")
            
            user = User(username)
            login_user(user, remember=True)
            
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('schedule'))
        except Exception as e:
            logging.error(f"Login failed: {e}")
            error = str(e)
            
    response = make_response(render_template('login.html', error=error, csrf_token=generate_csrf()))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/schedule', methods=['GET', 'POST'])
@token_required
def schedule():
    logging.info("Entering schedule route")
    logging.info(f"Request method: {request.method}")
    logging.info(f"Session data at start of schedule: {dict(session)}")
    logging.info(f"Cookies: {request.cookies}")
    
    if 'token' not in session:
        logging.error("No token in session")
        return redirect(url_for('login', next=request.url))
        
    try:
        token = session['token']
        if not token:
            logging.error("Token is empty")
            return redirect(url_for('login', next=request.url))
            
        # Test token validity
        try:
            test_response = api_get("/api/schoolyear/1/10000", token)
            if not test_response:
                logging.error("Token test failed")
                return redirect(url_for('login', next=request.url))
        except Exception as e:
            logging.error(f"Token test error: {e}")
            return redirect(url_for('login', next=request.url))
            
        schedule = None
        error = None
        selected_week = int(request.form.get('week', 36)) if request.method == 'POST' else 36
        allowed_weeks = [36, 37, 38, 39, 40, 41]

        if selected_week not in allowed_weeks:
            return render_template('index.html', error="Tuần không hợp lệ", csrf_token=generate_csrf())

        try:
            now = datetime.utcnow()
            semester_id = session.get('semester_id')
            expiry_str = session.get('semester_id_expiry')
            expired = True
            if semester_id and expiry_str:
                try:
                    expiry = datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%S")
                    expired = now >= expiry
                except ValueError:
                    expired = True

            if not semester_id or expired:
                try:
                    semester_id = get_latest_semester_id(session['token'])
                    session['semester_id'] = semester_id
                    session['semester_id_expiry'] = (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
                except Exception as e:
                    logging.error(f"Error getting semester ID: {e}")
                    error = "Không thể lấy thông tin học kỳ. Vui lòng thử lại sau."
                    return render_template('index.html', schedule=None, error=error, selected_week=selected_week, csrf_token=generate_csrf())

            # Kiểm tra cache cho lịch học
            schedule_cache = session.get('schedule_cache')
            schedule_cache_expiry = session.get('schedule_cache_expiry')
            cache_expired = True
            
            if schedule_cache and schedule_cache_expiry:
                try:
                    cache_expiry = datetime.strptime(schedule_cache_expiry, "%Y-%m-%dT%H:%M:%S")
                    cache_expired = now >= cache_expiry
                except ValueError:
                    cache_expired = True

            if not schedule_cache or cache_expired:
                try:
                    schedule_url = f"/api/StudentCourseSubject/studentLoginUser/{semester_id}"
                    full_schedule = api_get(schedule_url, token)
                    session['schedule_cache'] = full_schedule
                    session['schedule_cache_expiry'] = (now + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S")
                except Exception as e:
                    logging.error(f"Error getting schedule: {e}")
                    error = "Không thể lấy lịch học. Vui lòng thử lại sau."
                    return render_template('index.html', schedule=None, error=error, selected_week=selected_week, csrf_token=generate_csrf())
            else:
                full_schedule = schedule_cache

            # Lọc lịch học theo tuần đã chọn
            schedule = []
            for subject in full_schedule:
                filtered_timetables = [
                    t for t in subject['courseSubject']['timetables']
                    if t['fromWeek'] <= selected_week <= t['toWeek']
                ]
                if filtered_timetables:
                    subject_copy = subject.copy()
                    subject_copy['courseSubject'] = subject_copy['courseSubject'].copy()
                    subject_copy['courseSubject']['timetables'] = filtered_timetables
                    schedule.append(subject_copy)

        except Exception as e:
            logging.error(f"Schedule error: {e}")
            error = str(e)
        
        response = make_response(render_template('index.html', schedule=schedule, error=error, selected_week=selected_week, csrf_token=generate_csrf()))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    except Exception as e:
        logging.error(f"Schedule route error: {e}")
        return redirect(url_for('login', next=request.url))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))

def get_latest_semester_id(token):
    data = api_get("/api/schoolyear/1/10000", token)
    semester_ids = [
        semester['semesterId']
        for year in data.get('content', [])
        for semester in year.get('children', [])
        if 'semesterId' in semester
    ]
    if not semester_ids:
        raise Exception("Không tìm thấy semesterId nào trong dữ liệu trả về.")
    return max(semester_ids)

@app.route('/tuition', methods=['GET'])
@login_required
@token_required
def tuition():
    error = None
    tuition_info = None

    try:
        token = session['token']
        
        # Check cache for tuition info
        tuition_info = get_cached_data('tuition_cache', 'tuition_cache_expiry')
        
        if not tuition_info:
            # Check cache for tuition list
            tuition_list = get_cached_data('tuition_list_cache', 'tuition_list_expiry')
            
            if not tuition_list:
                tuition_list = api_get("/api/student/viewstudentpayablebyLoginUser", token)
                set_cached_data('tuition_list_cache', 'tuition_list_expiry', tuition_list)

            if tuition_list and tuition_list.get('receiveAbleNotCompleteDtos'):
                receive_id = tuition_list['receiveAbleNotCompleteDtos'][0]['id']
                tuition_info = api_get(f"/api/studenttuitionfeecalculate/findDtoByReceivePayableId/{receive_id}", token)
                set_cached_data('tuition_cache', 'tuition_cache_expiry', tuition_info)
            else:
                error = "Không tìm thấy khoản thu nào."

    except Exception as e:
        error = str(e)

    response = make_response(render_template('tuition.html', tuition_info=tuition_info, error=error))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

def get_tuition_detail_by_receive_id(receive_id, token):
    endpoint = f"/api/studenttuitionfeecalculate/findDtoByReceivePayableId/{receive_id}"
    return api_get(endpoint, token)

if __name__ == '__main__':
    app.run(debug=True)