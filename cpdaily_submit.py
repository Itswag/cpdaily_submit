# -*_coding:utf8-*-
import json
import smtplib
import sys
import time
from email.header import Header
from email.mime.text import MIMEText
from datetime import datetime
from lxml import etree
import requests
import base64
import random
import math
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import re


loginUrl = 'http://authserver.xxx.edu.cn/authserver/login?service=https%3A%2F%2Fxxx.cpdaily.com%2Fportal%2Flogin' # 学校登陆网址
xh = '********'  #  学号
pwd = '********'  #  密码

receivers = ['*********']  # 接收邮箱,可设置为你的QQ邮箱或者其他邮箱
sender = 'test@srblog.cn'  # 发信账号
password1 = '***********'  # 密钥
smtp_server = 'smtp.exmail.qq.com' # 以腾讯企业邮箱smtp服务器为例

# 模拟前端CryptoJS加密
aes_chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
aes_chars_len = len(aes_chars)
def randomString(len):
  retStr = ''
  i=0
  while i < len:
    retStr += aes_chars[(math.floor(random.random() * aes_chars_len))]
    i=i+1
  return retStr

def add_to_16(s):
    while len(s) % 16 != 0:
        s += '\0'
    return str.encode(s,'utf-8')

def getAesString(data,key,iv):  # AES-128-CBC加密模式，key需要为16位，key和iv可以一样
    key = re.sub('/(^\s+)|(\s+$)/g', '', key)
    aes = AES.new(str.encode(key),AES.MODE_CBC,str.encode(iv))
    pad_pkcs7 = pad(data.encode('utf-8'), AES.block_size, style='pkcs7')  # 选择pkcs7补全
    encrypted =aes.encrypt(pad_pkcs7)
    # print(encrypted)
    return str(base64.b64encode(encrypted),'utf-8')

def encryptAES(data,aesKey):
    encrypted =getAesString(randomString(64)+data,aesKey,randomString(16))
    return encrypted

def submit():
    flag = 0
    while True:
        flag+=1
        server = requests.session()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.16 Safari/537.36 Edg/79.0.309.12'
        }
        login_html = server.get(loginUrl, headers=headers).text
        html = etree.HTML(login_html)
        element = html.xpath('/html/script')[1].text # 获取加密密钥

        # 获取表单项
        pwdDefaultEncryptSalt = element.split('\"')[3].strip()
        lt = html.xpath("//input[@type='hidden' and @name='lt']")[0].attrib['value']
        dllt = html.xpath("//input[@type='hidden' and @name='dllt']")[0].attrib['value']
        execution = html.xpath("//input[@type='hidden' and @name='execution']")[0].attrib['value']
        rmShown = html.xpath("//input[@type='hidden' and @name='rmShown']")[0].attrib['value']

        password = encryptAES(pwd, pwdDefaultEncryptSalt)  # 加密密码
        # TODO
        # 验证码 配合OCR识别
        # url = 'http://authserver.xxx.edu.cn/authserver/needCaptcha.html'
        # params1 = {
        #     'username': xh,
        #     'pwdEncrypt2': 'pwdEncryptSalt',
        #     '_': datetime.now()
        #
        # }
        # res = server.get(url, headers=headers, params=params1).text

        params = {
            "username": xh,
            "password": password,
            "lt": lt,
            "dllt": dllt,
            "execution": execution,
            "_eventId": "submit",
            "rmShown": rmShown
        }

        res = server.post(loginUrl, data=params, headers=headers)
        # 登陆成功后获取cookie (MOD_AUTH_CAS项)
        cookies = server.cookies

        # 携带cookie查询最新待提交表单
        queryCollectWidUrl = 'https://xxx.cpdaily.com/wec-counselor-collector-apps/stu/collector/queryCollectorProcessingList'
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 4.4.4; OPPO R11 Plus Build/KTU84P) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Safari/537.36 yiban/8.1.11 cpdaily/8.1.11 wisedu/8.1.11',
            'content-type': 'application/json',
            'Accept-Encoding': 'gzip,deflate',
            'Accept-Language': 'zh-CN,en-US;q=0.8',
            'Content-Type': 'application/json;charset=UTF-8'
        }

        params = {
            'pageSize': 6,
            'pageNumber': 1
        }

        res = server.post(queryCollectWidUrl, headers=headers, cookies=cookies, data=json.dumps(params))

        if len(res.json()['datas']['rows']) < 1:
            print("当前暂无问卷提交任务(是否已完成)"+res.text)
            if flag > 3:
                mail("今日重试次数过多,请手动提交!")
                print(server.get("https://xxx.cpdaily.com/portal/logout", cookies=cookies))  # 退出登录
                time.sleep(24 * 60 * 60)
                continue
                # return "今日重试次数过多,请手动提交!"
            server.get("https://xxx.cpdaily.com/portal/logout", cookies=cookies) # 退出登录
            time.sleep(1*60*60)
            continue
        row = res.json()['datas']['rows'][0]
        if row['isHandled'] == 1:
            print("今日已经填写:" + res.text)
            mail("今日已经填写")
            server.get("https://xxx.cpdaily.com/portal/logout", cookies=cookies)
            time.sleep(24 * 60 * 60)
            continue
        collectWid = res.json()['datas']['rows'][0]['wid']
        formWid = res.json()['datas']['rows'][0]['formWid']

        res = requests.post(url='https://xxx.cpdaily.com/wec-counselor-collector-apps/stu/collector/detailCollector',
                            headers=headers, cookies=cookies, data=json.dumps({"collectorWid": collectWid}))
        schoolTaskWid = res.json()['datas']['collector']['schoolTaskWid'] # 这里也可抓包获取

        res = requests.post(url='https://xxx.cpdaily.com/wec-counselor-collector-apps/stu/collector/getFormFields',
                            headers=headers, cookies=cookies, data=json.dumps(
                {"pageSize": 30, "pageNumber": 1, "formWid": formWid, "collectorWid": collectWid})) # 当前我们需要问卷选项有21个，pageSize可适当调整

        form = res.json()['datas']['rows']
        # 过滤表单 选项 isSelected 属性
        for i in range(len(form) - 1, -1, -1):
            if form[i]['fieldItems']:
                Items = form[i]['fieldItems']
                for item in Items[:]:
                    if item['isSelected']:
                        continue
                    else:
                        Items.remove(item)
            else:
                continue

        headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 4.4.4; OPPO R11 Plus Build/KTU84P) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Safari/537.36 okhttp/3.12.4',
            'CpdailyStandAlone': '0',
            'extension': '1',
            'Cpdaily-Extension': '',
            'Content-Type': 'application/json; charset=utf-8',
            'Host': 'xxx.cpdaily.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        # 地址根据学校要求填写即可
        params = {"formWid": formWid, "address": "定位失败",
                  "collectWid": collectWid, "schoolTaskWid": schoolTaskWid,
                  "form": form
        }

        r = server.post("http://xxx.cpdaily.com/wec-counselor-collector-apps/stu/collector/submitForm",
                        headers=headers, cookies=cookies, data=json.dumps(params))
        msg = r.json()['message']
        server.get("https://xxx.cpdaily.com/portal/logout",cookies=cookies)

        if msg == 'SUCCESS':
            print('今日提交成功！24小时后，脚本将再次自动提交')
            message = '今日提交成功！24小时后，脚本将再次自动提交'
            mail(message)
            time.sleep(24 * 60 * 60)
            continue
        elif msg == '该收集已填写无需再次填写':
            print('该收集已填写无需再次填写')
            message = '该收集已填写无需再次填写'
            mail(message)
            time.sleep(24 * 60 * 60)
            continue
        else:
            print('失败' + r.text)
            message = '出错了，错误如下 ' + r.text
            if flag > 3:
                mail(message+"今日重试次数过多,请手动提交!")
                time.sleep(24 * 60 * 60)
                continue
                # return "今日重试次数过多,请手动提交!"
            time.sleep(1 * 60 * 60)
            continue
        # return message

def mail(msg):
    message = MIMEText(msg, 'plain', 'utf-8')
    message['From'] = Header(sender, 'utf-8')  # 发送者
    message['To'] = Header(receivers, 'utf-8')  # 接收者
    message['Subject'] = Header("今日校园打卡情况推送-"+time.strftime('%m-%d %H:%M', time.localtime(time.time())), 'utf-8')
    server = smtplib.SMTP_SSL(smtp_server, 465)
    server.login(sender, password1)
    server.sendmail(sender, receivers, message.as_string())
    server.quit()


if __name__ == '__main__':
    try:
        submit()
    except Exception as e:
        print(e)
        mail("程序异常%s"%e)
        exit(-1)
