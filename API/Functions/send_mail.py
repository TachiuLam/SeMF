# -*- coding: utf-8 -*-
# Tachiu Lam
# techaolin@gamil.com
# 2020/11/18 14:23

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication



class SendMail:
    @staticmethod
    def send_mail(mail_info):
        text_apart = MIMEText(mail_info.get('content'))
        # excel_file = mail_info.get('filepath')
        # excel_file_name = mail_info.get('filename')
        # excel_apart = MIMEApplication(open(excel_file, 'rb').read())
        # excel_apart.add_header('Content-Disposition', 'attachment', filename=excel_file_name)

        m = MIMEMultipart()
        # m.attach(excel_apart)
        m.attach(text_apart)
        m['Subject'] = mail_info.get('title')
        m['from'] = mail_info.get('from_addr')
        m['to'] = ','.join(mail_info.get('toaddrs'))

        try:
            server = smtplib.SMTP(mail_info.get('mail_server'))
            server.login(mail_info.get('from_addr'), mail_info.get('password'))
            server.sendmail(mail_info.get('from_addr'), mail_info.get('toaddrs'), m.as_string())
            print('report has sended to your email !')
            server.quit()
        except smtplib.SMTPException as e:
            print('fail to send email:', e)  # 打印错误


if __name__ == '__main__':
    from API.Functions.alert_info import nat_mail_info
    SendMail.send_mail(nat_mail_info)