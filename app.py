from flask import Flask, render_template, request, redirect, url_for, session, make_response
import requests
import urllib3
from datetime import datetime, timedelta
import logging
import os
from flask_wtf.csrf import CSRFProtect, generate_csrf # type: ignore
from flask_login import login_required, LoginManager, UserMixin, login_user, logout_user, current_user # type: ignore

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')  # Đặt biến môi trường cho secret_key

# Cấu hình logging
logging.basicConfig(level=logging.INFO)

API_BASE = "https://sinhvien1.tlu.edu.vn/education"

csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # tên route login

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    # Ở đây bạn có thể lấy user từ database, ví dụ:
    return User(user_id)

def api_post(endpoint, data, token=None, timeout=30):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
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

def api_get(endpoint, token=None, timeout=30):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
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
    if request.method == 'GET':
        session.clear()
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
            resp = api_post("/oauth/token", login_data)
            token = resp["access_token"]
            session['username'] = username
            session['token'] = token
            user = User(username)
            login_user(user)
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
@login_required
def schedule():
    if 'token' not in session:
        return redirect(url_for('login'))

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
            expiry = datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%S")
            expired = now >= expiry

        if not semester_id or expired:
            semester_id = get_latest_semester_id(session['token'])
            session['semester_id'] = semester_id
            session['semester_id_expiry'] = (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")

        # Kiểm tra cache cho lịch học
        schedule_cache = session.get('schedule_cache')
        schedule_cache_expiry = session.get('schedule_cache_expiry')
        cache_expired = True
        
        if schedule_cache and schedule_cache_expiry:
            cache_expiry = datetime.strptime(schedule_cache_expiry, "%Y-%m-%dT%H:%M:%S")
            cache_expired = now >= cache_expiry

        if not schedule_cache or cache_expired:
            token = session['token']
            schedule_url = f"/api/StudentCourseSubject/studentLoginUser/{semester_id}"
            full_schedule = api_get(schedule_url, token)
            session['schedule_cache'] = full_schedule
            session['schedule_cache_expiry'] = (now + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S")
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
    return render_template('index.html', schedule=schedule, error=error, selected_week=selected_week, csrf_token=generate_csrf())

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

if __name__ == '__main__':
    app.run(debug=True)