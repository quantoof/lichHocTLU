import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

username = "2251162125"
password = "Osascomp@204"
user_id = "12"

login_url = "https://sinhvien1.tlu.edu.vn/education/oauth/token"
login_data = {
    "client_id": "education_client",
    "grant_type": "password",
    "username": username,
    "password": password,
    "client_secret": "password"
}

resp = requests.post(login_url, data=login_data, verify=False)
token = resp.json()["access_token"]

schedule_url = f"https://sinhvien1.tlu.edu.vn/education/api/StudentCourseSubject/studentLoginUser/{user_id}"
headers = {"Authorization": f"Bearer {token}"}
schedule_resp = requests.get(schedule_url, headers=headers, verify=False)
print(schedule_resp.json())