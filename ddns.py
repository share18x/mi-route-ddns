#!/usr/bin/env python
# coding=utf-8
import requests
from Crypto.Hash import SHA
import random
import time
import json
import re
import os


def getToken(host, pwdtext):

    homeRequest = requests.get('http://' + host + '/cgi-bin/luci/web/home')
    key = re.findall(r'key: \'(.*)\',', homeRequest.text)[0]
    mac = re.findall(r'deviceId = \'(.*)\';', homeRequest.text)[0]

    aimurl = "http://" + host + "/cgi-bin/luci/api/xqsystem/login"

    nonce = "0_" + mac + "_" + str(int(time.time())) + "_" + str(random.randint(1000, 10000))

    pwd = SHA.new()
    pwd.update((pwdtext + key).encode('utf-8'))
    hexpwd1 = pwd.hexdigest()

    pwd2 = SHA.new()
    pwd2.update((nonce + hexpwd1).encode('utf-8'))
    hexpwd2 = pwd2.hexdigest()

    data = {
        "logtype": 2,
        "nonce": nonce,
        "password": hexpwd2,
        "username": "admin"
    }

    response = requests.post(url=aimurl, data=data, timeout=5)
    resjson = json.loads(response.content)

    if resjson['code'] == 0:
        return resjson['token']
    else:
        return False


def getInfo(host, token, action=None):
    wan_url = 'http://'+ host + '/cgi-bin/luci/;stok='+ token + '/api/xqnetwork/wan_info'
    global ipv4_local

    if action == 'ddns':
        while True:
            ipv4_local = getWanInfo(wan_url)
            doDDNS(ddns_address=ddns_address, password=password, switch_ipv4=switch_ipv4, switch_ipv6=switch_ipv6)
            time.sleep(600)
    else:
        pass


def getWanInfo(url):
    try:
        wanInfo = json.loads(requests.get(url,timeout=5).content)
        return wanInfo['info']['ipv4'][0]['ip']
    except Exception as e:
        print (e)


def doDDNS(ddns_address, password, switch_ipv4=0, switch_ipv6=0):
    # 读取域名对应的ip地址
    ip_web = os.popen(f"nslookup {ddns_address}").read()
    re1 = re.compile('(10(?:\.\d+){3})')
    re2 = re.compile('(2001(?::\w{0,4}){2,})') 
    ipv4_web = re.search(re1, ip_web)
    ipv6_web = re.search(re2, ip_web)

    if ipv4_web is not None:
        ipv4_web = ipv4_web.group(1)
    if ipv6_web is not None:
        ipv6_web = ipv6_web.group(1)

    str_1 = re.compile('good')
    str_2 = re.compile('bad')
    str_3 = re.compile('nochg')

    connect = requests.session()

    if switch_ipv4 == 1:
        if ipv4_local != ipv4_web:
            result = connect.get(f'http://{ddns_address}:{password}@dyn.dns.he.net/nic/update?hostname={ddns_address}&myip={ipv4_local}')
            res_1 = re.search(str_1, result.text)
            res_2 = re.search(str_2, result.text)
            res_3 = re.search(str_3, result.text)
            if res_2:
                print('验证错误，请检查输入')
            elif res_1:
                print(f'ipv6成功更新：\n旧地址：{ipv4_web}\n新地址：{ipv4_local}')
            elif res_3:
                print(f'ipv6已经更新：\n旧地址：{ipv4_web}\n新地址：{ipv4_local}')
        else:
            print('ipv4没有变化')
    
    if switch_ipv6 == 1:
        if ipv6_local != ipv6_web:
            result = connect.get(f'http://{ddns_address}:{password}@dyn.dns.he.net/nic/update?hostname={ddns_address}&myip={ipv6_local}')
            res_1 = re.search(str_1, result.text)
            res_2 = re.search(str_2, result.text)
            res_3 = re.search(str_3, result.text)
            if res_2:
                print('验证错误，请检查输入')
            elif res_1:
                print(f'ipv6成功更新：\n旧地址：{ipv6_web}\n新地址：{ipv6_local}')
            elif res_3:
                print(f'ipv6已经更新：\n旧地址：{ipv6_web}\n新地址：{ipv6_local}')
        else:
            print('ipv6没有变化')


if __name__ == '__main__':
    # 填入路由器ip
    host = ''
    # 填入路由器密码
    pwdtext = ''
    # 填入域名
    ddns_address = ''
    # 填入域名的token
    password = ''
    switch_ipv4 = 1
    # 默认关闭ipv6
    switch_ipv6 = 0
    
    token = getToken(host, pwdtext)

    if token:
        getInfo(host, token, action='ddns')
    else:
        print ('Login failed!')
