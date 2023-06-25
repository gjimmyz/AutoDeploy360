#!/usr/bin/python
# -*- coding: utf-8 -*-
#--------------------------------------------------
#Author:gong_zheng
#Email:gong_zheng@mingmatechs.com
#FileName:mailsend.py
#Function:
#Version:1.0
#Created:2019-06-17
#--------------------------------------------------
import sys
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.utils import COMMASPACE
from email.mime.multipart import MIMEMultipart

def send_mail(mail_host, fro, to, subject, text, txttype='html', files=[]):
    msg = MIMEMultipart()
    msg['From'] = fro
    msg['Subject'] = subject
    msg['To'] = COMMASPACE.join(to)
    if txttype=="html":
        msg.attach(MIMEText(text,'html'))
    else:
        msg.attach(MIMEText(text))
    for file in files:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(open(file, 'r').read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(file))
        msg.attach(part)

    s = smtplib.SMTP(mail_host)
    s.sendmail(fro,to,msg.as_string())
    s.quit()

if __name__=='__main__':
    mail_host = sys.argv[1]
    fro = sys.argv[2]
    to = sys.argv[3].split(',')
    subject = sys.argv[4]
    with open(sys.argv[5],"r") as f:
        text='<pre>' + f.read() + '</pre>'
    txttype='html'
    files=[]
    send_mail(mail_host, fro, to, subject, text, txttype, files)
