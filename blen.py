# coding: utf-8
from __future__ import print_function

import os
import sys
import argparse
import logging 
import time
import threading
import configparser
import requests
import ctypes
import inspect
import subprocess
import re


import lib.core
from lib.core.data import root_path

from lib.core.common import get_local_version
from lib.core.center import oFxCenter
sys.path.append(root_path)



logo = '''

                                                
                                                
\033[33m`7MM"""Yp, `7MMF'      `7MM"""YMM  `7MN.   `7MF'
\033[33m  MM    Yb   MM          MM    `7    MMN.    M  
\033[31m  MM    dP   MM          MM   d      M YMb   M  
\033[31m  MM"""bg.   MM          MMmmMM      M  `MN. M\033[0m  
\033[35m  MM    `Y   MM      ,   MM   Y  ,   M   `MM.M  
\033[35m  MM    ,9   MM     ,M   MM     ,M   M     YMM  
\033[32m.JMMmmmd9  .JMMmmmmMMM .JMMmmmmMMM .JML.    YM  Author : openx-org\033  Version : {version} 

\033[32m    #*#*#  https://github.com/openx-org/BLEN  #*#*#

\033[33m       _-___________________________________-_
                
\033[0m'''.format(version=get_local_version(root_path+"/info.ini"))



def main():

    print(logo)

    ofxcenter = oFxCenter()
    
    
    
if __name__ == "__main__":
    main()