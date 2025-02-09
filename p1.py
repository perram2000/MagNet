import boto3
import subprocess
import importlib.util
from timer import Timer  # 导入 Timer 类
import requests
import json
import os
import time
import validators
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from smtplibaio import SMTP_SSL



# 初始化 S3 客户端
s3 = boto3.client('s3')
bucket_name = 'magnet-hkmu'  # 替换为你的 S3 存储桶名称


# 上传文件到 S3
def upload_to_s3(file_name, object_name=None):
    if object_name is None:
        object_name = file_name
    s3.upload_file(file_name, bucket_name, object_name)
    print(f"Uploaded {file_name} to {bucket_name}/{object_name}")


# 从 S3 下载文件
def download_from_s3(object_name, file_name=None):
    if file_name is None:
        file_name = object_name
    s3.download_file(bucket_name, object_name, file_name)
    print(f"Downloaded {bucket_name}/{object_name} to {file_name}")


def scan_file_with_virustotal(file_path):
    # 替换为你的 VirusTotal API 密钥
    scan_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    report_url = 'https://www.virustotal.com/vtapi/v2/file/report'
    api_key = "5a2bba7b0b72981cd2af998d253e5c2e76cc210f710ed5423b0af69e29114ac1"
    """使用 VirusTotal API 扫描文件，检测是否包含病毒或木马程序"""
    try:
        # 上传文件到 VirusTotal
        with open(file_path, 'rb') as f:
            files = {'file': (file_path, f)}
            params = {'apikey': api_key}
            response = requests.post(scan_url, files=files, params=params)

        if response.status_code != 200:
            print(f"Error uploading file to VirusTotal: {response.text}")
            return False

        scan_id = response.json().get('scan_id')
        if not scan_id:
            print("Failed to retrieve scan ID.")
            return False

        # 获取扫描报告
        params = {'apikey': api_key, 'resource': scan_id}
        while True:
            response = requests.get(report_url, params=params)
            result = response.json()
            if result['response_code'] == 1:
                # 检查检测结果
                positives = result.get('positives', 0)
                if positives == 0:
                    print(f"No virus found in {file_path}")
                    return True  # 文件安全
                else:
                    print(f"Virus detected in {file_path}")
                    # 生成详细报告
                    makeitlooknicer(result)
                    return False  # 文件不安全
            else:
                print("Waiting for scan report...")
                time.sleep(15)
    except Exception as e:
        print(f"An error occurred while scanning the file: {e}")
        return False


def makeitlooknicer(res):
    """生成更详细的扫描报告"""
    try:
        permalink = res['permalink']
        shorturl = shorten(permalink)
        scans = res['scans']

        char_to_replace = {
            ": {'detected': True, 'result': 'malicious site'},": " thinks this site is malicious",
            ": {'detected': False, 'result': 'clean site'},": " thinks this site is clean",
            ": {'detected': False, 'result': 'unrated site'},": " does not know the proper rating of this site",
            "'": ""
        }

        # 格式化扫描结果
        formatted_result = str(scans).replace("},", "}, \n")[1:][:-1] + ","
        for key, value in char_to_replace.items():
            formatted_result = formatted_result.replace(key, value)

        formatted_result = formatted_result + "\nThe URL to VirusTotal scan results is: " + permalink + " or " + shorturl
        formatted_result = "\n".join([line[1:] if line.startswith(" ") else line for line in formatted_result.splitlines()])

        print(formatted_result)
    except Exception as e:
        print(f"An error occurred while formatting the report: {e}")


def shorten(permalink):
    """将长链接缩短"""
    try:
        res = requests.get("http://tinyurl.com/api-create.php?url=" + permalink)
        return res.text
    except Exception as e:
        print(f"An error occurred while shortening the URL: {e}")
        return permalink



# 上传数据


# 上传数据
def load_data(data):
    with open(r'R:\MagNet\data.json', 'w') as f:
        json.dump(data, f)

    if scan_file_with_virustotal(r'R:\MagNet\data.json'):
        upload_to_s3(r'R:\MagNet\data.json', 'data_p1.json')
    else:
        print("Data file contains a virus or is unsafe. Upload aborted.")


# 下载数据
def download_data():
    download_from_s3('data_p1.json', 'data.json')
    with open('data.json', 'r') as f:
        data = json.load(f)
    return data


# 创建和保存计算任务
def task_create():
    task_code = """
def task(n):
    def fibonacci(n):
        if n <= 0:
            return 0
        elif n == 1:
            return 1
        else:
            return fibonacci(n-1) + fibonacci(n-2)
    result = fibonacci(n)
    print(result)
    return result
"""
    with open(r'R:\MagNet\task_todo.py', 'w') as f:
        f.write(task_code)
    print("Task created and saved to task_todo.py")


# 上传任务代码
def load_task():
    task_file = r'R:\MagNet\task_todo.py'


    upload_to_s3(task_file, 'task_p1.py')


# 下载任务代码
def download_task():
    download_from_s3('task_p1.py', 'task_todo.py')


# 动态加载并执行任务
def calculate(data):
    try:
        spec = importlib.util.spec_from_file_location("task_todo", r"R:\MagNet_p1\task_todo.py")
        task_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(task_module)

        if hasattr(task_module, 'task'):
            result = task_module.task(data)
            print(f"Calculation result: {result}")
            return result
        else:
            print("The 'task' function is not found in the downloaded task file.")
            return None
    except FileNotFoundError:
        print("The downloaded task file is not found. Please make sure it is downloaded and saved as 'task_todo.py'.")
        return None
    except Exception as e:
        print(f"An error occurred while executing the task: {e}")
        return None


# 上传计算结果
def load_result(result):
    # 将结果保存到本地文件
    local_path = r'R:\MagNet_p1\result.json'
    with open(local_path, 'w') as f:
        json.dump(result, f)

    # 上传文件到 Amazon S3
    upload_to_s3(local_path, 'result.json')
    print("Result file uploaded to S3")


# 下载计算结果
def download_result():
    download_from_s3('result.json')
    with open(r'R:\MagNet\result.json', 'r') as f:
        result = json.load(f)
    return result


def calculate_service_price(start_time, end_time):
    # 算力价格 ($/秒)
    price_per_second = 0.05

    # MagNet 平台服务费比率
    service_fee_ratio = 0.15

    # 计算服务时间 (秒)
    service_time = end_time - start_time

    # 计算服务价格
    service_price = service_time * price_per_second * (1 - service_fee_ratio)
    print(service_price)
    print('Service price is', service_price)

    return service_price


async def run_task(result):
    # 邮件服务器设置
    smtp_server = 'smtp.gmail.com'
    smtp_port = 465  # 使用 SSL 端口
    smtp_username = 'fuyuhao629@gmail.com'  # should be MagNet@gmail.com
    smtp_password = 'lwus gtqa lksy kblx'
    to_email = 's1298721@live.hkmu.edu.hk'

    if result is None:
        # 任务正在处理中的邮件主题和内容
        subject = "Task In Progress"
        message = "The task is currently being processed."
    else:
        # 任务已完成的邮件主题和内容
        subject = "Task Completed"
        message = "The task has been completed successfully."

    # 创建邮件消息
    msg = MIMEMultipart()
    msg['From'] = smtp_username
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'plain'))

    try:
        # 创建 SMTP_SSL 连接
        async with SMTP_SSL(smtp_server, smtp_port) as server:
            await server.login(smtp_username, smtp_password)
            await server.sendmail(smtp_username, to_email, msg.as_string())
        print(f"Email notification sent to {to_email}")
    except Exception as e:
        print(f"Error sending email notification: {str(e)}")

def simulate_user_u1():
    # 创建一些示例数据
    data = input('please input your data here(integer): ')

    try:
        data = int(data)
        load_data(data)
        print("Data loaded to the cloud.")
    except ValueError:
        print("please input integer")# 计算150位斐波那契数列


    # 调用 task_create 函数创建任务代码
    task_create()
    print("Task created.")

    # 调用 load_task 函数将任务代码上传到云平台
    load_task()
    print("Task code loaded to the cloud.")





def simulate_user_p1():
    # 创建
    # 计算30位斐波那契数列

    # 调用 load_data 函数将数据上传到云平台
    download_data()
    print('Data downloaded from cloud.')

    download_task()
    print("task downloaded from the cloud.")

    data_a = download_data()

    result_a = calculate(data_a)
    print("Data calculated from cloud.")

    load_result(result_a)






def create_starttime():
    start_time = time.time()
    return start_time


def endtime():
    end_time = time.time()
    return end_time


def load_starttime(start_time):
    # 将 start_time 转换为字符串格式
    start_time_str = str(start_time)

    # 创建 JSON 对象
    data = {
        'start_time': start_time_str
    }

    # 将 JSON 对象写入文件
    with open('start_time.json', 'w') as file:
        json.dump(data, file)

    # 上传文件到 Amazon S3
    upload_to_s3('start_time.json')

import json

def download_starttime():
    # 从 Amazon S3 下载文件
    download_from_s3('start_time.json')

    # 读取 JSON 文件
    with open('start_time.json', 'r') as file:
        data = json.load(file)

    # 获取 start_time 值并转换为浮点数
    start_time = float(data['start_time'])

    return start_time


# 执行模拟用户 U1 的操作
#main function
if __name__ == "__main__":

    command = input('dispatch computing tasks(USER) / process computing tasks(PROVIDER)')
    command_1 = command.upper()
    if command_1 == 'USER':
        simulate_user_u1()
        st = create_starttime()
        load_starttime(st)

    elif command_1 == 'PROVIDER':
        simulate_user_p1()
        st_1 = download_starttime()
        et = endtime()

        calculate_service_price(st_1, et)
    else:
        print("please select a valid command(USER/PROVIDER)")

