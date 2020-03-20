# -*- coding: utf-8 -*-
__author__ = 'mehmet şerif paşa'

import re
import sys
import time
import json
import socket
import random
import argparse
import requests
from bs4 import BeautifulSoup

try:
    import colorama
except ImportError:
    print("No module named 'Colorama' found")

try:
    from googlesearch import search
except ImportError:
    print("No module named 'google' found")

## parse section
parse = argparse.ArgumentParser()
parse.add_argument('-u', '--url', help='example: http://evil.com')
parse.add_argument('-o', '--output', help='example: output.txt')
args = parse.parse_args()
host = args.url
output = args.output


class Machine:

    def __init__(self, host, output):
        self.host = host
        self.output = output
        self.SCANNER_URL = []
        self.SCANNER_URL_CONTROL = []
        self.SCANNER_URL_PATH = []
        self.STAGE_2_URL = []
        self.TOTAL_URL = []
        self.USERAGENT = [agent.strip() for agent in open('useragent.txt')]
        self.Random_Useragent = random.choice(self.USERAGENT)
        # github.com/jhaddix/LinkFinder/blob/master/linkfinder.py >> Thanks to Haddix for regex
        self.REGEX = re.compile(r""" 
                  ([^\n]*(?:"|')                    # Start newline delimiter
                  (?:
                    ((?:[a-zA-Z]{1,10}://|//)       # Match a scheme [a-Z]*1-10 or //
                    [^"'/]{1,}\.                    # Match a domainname (any character + dot)
                    [a-zA-Z]{2,}[^"']{0,})          # The domainextension and/or path
                    |
                    ((?:/|\.\./|\./)                # Start with /,../,./
                    [^"'><,;| *()(%$^/\\\[\]]       # Next character can't be... 
                    [^"'><,;|()]{1,})               # Rest of the characters can't be
                    |
                    ([a-zA-Z0-9/]{1,}/              # Relative endpoint with /
                    [a-zA-Z0-9/]{1,}\.[a-z]{1,4}    # Rest + extension
                    (?:[\?|/][^"|']{0,}|))          # ? mark with parameters
                    |
                    ([a-zA-Z0-9]{1,}                # filename
                    \.(?:php|asp|aspx|jsp)          # . + extension
                    (?:\?[^"|']{0,}|))              # ? mark with parameters

                  )             

                  (?:"|')[^\n]*)                    # End newline delimiter
                """, re.VERBOSE)
        self.REGEX_2 = 'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        self.REGEX_3 = 'http[s]?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'

    def Output(self, put):
        self.file = open(str(self.output), "a+")
        self.file.writelines(str(put) + "\n")

    def Request(self):
        # İstek burda yapılıyor ve bunun üzerinden işlem yapılıyor.
        self.req = requests.get(self.host)  # Siteye GET isteği yapılmıştır
        self.req_content = self.req.content  # Sitenin kaynak bilgisi
        self.req_headers = self.req.headers  # Sitenin Headers bilgisi
        self.req_status_code = self.req.status_code  # Sitenin durum kodu (200,301 vs.)
        self.req_history = self.req.history  # Sitedeki yönlendirmeleri gösteriyor
        self.req_text = self.req.text  # Düzenli bir şekilde kaynak kodu

    def Host_Look(self):
        # Düzenli gözükmesi için verilen site url'sini,  split işlemine sokarak temiz bir host elde ediyoruz.
        self.host_strip = self.host.split("://")[1]
        print(colorama.Fore.GREEN + "Taranan Site: " + colorama.Style.RESET_ALL + self.host_strip)
        Object_1.Output("Taranan Site: " + self.host_strip)

    def Ip_Look(self):
        # Verdiğimiz sitenin ip bilgisini veriyor
        self.host_ip = socket.gethostbyname(self.host_strip)
        print(colorama.Fore.GREEN + "Ip Adresi: " + colorama.Style.RESET_ALL + self.host_ip)
        Object_1.Output("Ip Adresi: " + self.host_ip)

    def Server_Check(self):
        # Headers bilgisinde yer alan bazı bilgileri derliyoruz.
        for i in self.req_headers.items():  # İtems ile headers üzerinde rahat işlem yapabiliyoruz
            if i[0] == 'Server':  # Server = kaynak sunucu tarafından kullanılan yazılım hakkında bilgi içerir.
                print(colorama.Fore.GREEN + "Server: " + colorama.Style.RESET_ALL + str(i[1]))
                Object_1.Output("Server: " + str(i[1]))
            if i[0] == 'X-Powered-By':  # Web uygulamasını destekleyen teknolojiyi (ör. ASP.NET, PHP, JBoss) belirtir
                print(colorama.Fore.GREEN + "X-Powered-By: " + colorama.Style.RESET_ALL + str(i[1]))
                Object_1.Output("X-Powered-By: " + str(i[1]))
            if i[0] == 'Access-Control-Allow-Origin':
                print(colorama.Fore.GREEN + "Access-Control-Allow-Origin: " + colorama.Style.RESET_ALL + str(i[1]))
                Object_1.Output("Access-Control-Allow-Origin: " + str(i[1]))
            if i[0] == 'Content-Security-Policy':
                print(colorama.Fore.GREEN + "Content-Security-Policy: " + colorama.Style.RESET_ALL + str(i[1]))
                Object_1.Output("Content-Security-Policy: " + str(i[1]))
            if i[0] == 'P3P':
                print(colorama.Fore.GREEN + "P3P: " + colorama.Style.RESET_ALL + str(i[1]))
                Object_1.Output("P3P: " + str(i[1]))
            else:
                pass

    def Robots_Txt(self):
        # Sitede robots dosyasını işliyoruz
        self.robots_txt = requests.get(self.host + '/robots.txt')
        self.robots_txt_text = self.robots_txt.text
        if self.robots_txt.status_code == 200:
            print(colorama.Fore.GREEN + "Robots.txt dosyası mevcut lütfen kontrol ediniz. " + colorama.Style.RESET_ALL)
            Object_1.Output("-" * 50)
        else:
            pass

    def Url_Crawler(self):  # Kaynak koddaki bütün urlleri aldık
        print(colorama.Fore.GREEN + "Page Content Urls:" + colorama.Style.RESET_ALL)
        self.sonuc = re.findall(self.REGEX_2, str(self.req_content))
        self.sonuc2 = re.findall(self.REGEX_3, str(self.req_content))
        Object_1.Output("-" * 50)
        Object_1.Output("Url List")
        for sonuc_string in set(self.sonuc):
            print(colorama.Fore.RED + "[+] " + colorama.Style.RESET_ALL + sonuc_string)
            if '?' in sonuc_string:  # Url leri alıyoruz
                self.SCANNER_URL.append(sonuc_string)
            Object_1.Output(sonuc_string)
        for sonuc2_string in set(self.sonuc2):
            print(colorama.Fore.RED + "[+] " + colorama.Style.RESET_ALL + sonuc2_string)
            Object_1.Output(sonuc2_string)

    def Google_Search_Path_Crawler(self):  # Google yardımıyla ek olarak 40 tane url aldık
        print(colorama.Fore.GREEN + "Google Search:" + colorama.Style.RESET_ALL)
        query = "site:" + str(self.host_strip)
        for j in search(query, num=40, stop=40, pause=2):
            print(colorama.Fore.RED + "[+] " + colorama.Style.RESET_ALL + str(j))
            self.SCANNER_URL.append(str(j))
            Object_1.Output(str(j))

    def Crawler_Url_Control(
            self):  # aldığımız domainlerin subdomaine uygunluğunu kontrol edicez www.google.com == www.google.com
        print(colorama.Fore.GREEN + "Control Section" + colorama.Style.RESET_ALL)
        if 'www' in self.host_strip:
            self.host_strip_control = str(self.host_strip).split('www.')[
                1]  # www. striplememizin nedeni google arama yaparken sıkıntı çıkarmaması için
        else:
            self.host_strip_control = str(self.host_strip)
        for i in self.SCANNER_URL:
            if self.host_strip_control in i:
                print(i)
                print("var")
        """
        en son yapılıcak burda bütün urllerin geçerliliğini kontrol
        """

    def URL_CRAWLER_WIDE_SCAN(self):
        print(colorama.Fore.GREEN + "Path: " + colorama.Style.RESET_ALL)
        for i in self.SCANNER_URL:
            i = i.decode("utf-8", "replace")
            if len(i.split('/')) > 2:
                for k in range(2, len(str(i).split('/'))):
                    if '?' in i.split('/')[k] or \
                            '/' in i.split('/')[k] or \
                            '&' in i.split('/')[k] or \
                            '"' in i.split('/')[k] or \
                            "'" in i.split('/')[k] or \
                            "\s" in i.split('/')[k] or \
                            "=" in i.split('/')[k] or \
                            ".com" in i.split('/')[k] or \
                            "." in i.split('/')[k]:
                        pass
                    else:
                        self.SCANNER_URL_PATH.append(i.split('/')[k])
                        Object_1.Output(str(i.split('/')[k]))

    def URL_CRAWLER_WIDE_SCANNER_stage_2(self):
        print(colorama.Fore.GREEN + "Stage 2:" + colorama.Style.RESET_ALL)
        if 'www' in self.host_strip:
            self.STAGE_2_strip = str(self.host_strip).split('www.')[
                1]  # www. striplememizin nedeni google arama yaparken sıkıntı çıkarmaması için
        else:
            self.STAGE_2_strip = str(self.host_strip)
        self.STAGE_2_REGEX = '.*' + self.STAGE_2_strip + '?'
        for i in set(self.SCANNER_URL_PATH):
            self.Url_crawler_stage_2_request = requests.get(host + '/' + str(i))
            try:
                self.Stage_2_sonuc = re.findall(self.REGEX_2, str(self.Url_crawler_stage_2_request.content))
                for k in set(self.Stage_2_sonuc):
                    if re.search(self.STAGE_2_REGEX, str(k)):
                        self.STAGE_2_URL.append(str(k))
                        print(colorama.Fore.RED + "[+] " + colorama.Style.RESET_ALL + str(k))
                        Object_1.Output(str(k))
            except:
                continue

    def LIST_combining(self):  # Bütün linkleri bir listede topluyoruz
        for i_1 in self.STAGE_2_URL:
            self.TOTAL_URL.append(i_1)
        for i_2 in self.SCANNER_URL_CONTROL:
            self.TOTAL_URL.append(i_2)
        for i_3 in self.SCANNER_URL_PATH:
            self.TOTAL_URL.append(i_3)
        for i_4 in self.STAGE_2_URL:
            self.TOTAL_URL.append(i_4)
        for total in self.TOTAL_URL:
            pass
            # print(colorama.Fore.RED + "[*]" + str(total)+ colorama.Style.RESET_ALL)


Object_1 = Machine(host, output)
Object_1.Request()
print("-" * 70)
Object_1.Server_Check()
Object_1.Host_Look()
Object_1.Ip_Look()
print("-" * 70)
Object_1.Robots_Txt()
print("-" * 70)
Object_1.Url_Crawler()
print("-" * 70)
Object_1.Google_Search_Path_Crawler()
print("-" * 70)
Object_1.URL_CRAWLER_WIDE_SCAN()
print("-" * 70)
Object_1.URL_CRAWLER_WIDE_SCANNER_stage_2()
print("-" * 70)
Object_1.LIST_combining()
print("-" * 70)




