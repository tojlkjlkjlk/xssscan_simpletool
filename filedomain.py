#-*- coding: UTF-8 -*-
import requests
import re
import sys
 
def writtarget(target):
        print target
        file = open('result.txt','a')
        with file as f:
                f.write(target+'\n')
 
        file.close()
 
 
def targetopen(httptarget , httpstarget):
 
 
        header = {
                'Connection': 'keep-alive',
                'Pragma': 'no-cache',
                'Cache-Control': 'no-cache',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                'DNT': '1',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8'
                }
 
        try:
            reponse_http = requests.get(httptarget, timeout=3, headers=header)
            code_http = reponse_http.status_code
            if (code_http == 200):
                    httptarget_result = re.findall('//.*', httptarget)
                    writtarget(httptarget_result[0][2:])
            else:
                    reponse_https = requests.get(httpstarget, timeout=3, headers=header)
                    code_https = reponse_https.status_code
                    if (code_https == 200):
                            httpstarget_result = re.findall('//.*', httpstarget)
                            writtarget(httpstarget_result[0][2:])
 
 
        except:
                pass
 
def domainscan(target):
 
        f = open('domain.txt','r')
        for line in f:
                httptarget_result = 'http://'+ line.strip() + '.'+target
                httpstarget_result = 'https://'+ line.strip() + '.'+target
 
                targetopen(httptarget_result, httpstarget_result)
 
        f.close()
 
if __name__ == "__main__":
        
        file = open('result.txt','w+')
        file.truncate()
        file.close()
        target = raw_input('PLEASE INPUT YOUR DOMAIN(Eg:ichunqiu.com):')
        print 'Starting.........'
        domainscan(target)
        print 'Done ! Results in result.txt'