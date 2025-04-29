import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_email(to, subject, code):
    msg = MIMEMultipart()
    msg['From'] = "VeriOne"
    msg['To'] = to
    msg['Subject'] = subject

    # Body of the email
    body = """
    <html>
      <body>
        <img style="width: 100%; height: auto;" src="https://res.cloudinary.com/dwe12qajs/image/upload/v1745912863/Frame_8679_1_mvjup2.png" style="max-width:100%; height:auto;">
        <h3>Account Verification</h3>
        <p>This is your VeriOne account verification code: <strong>{code}</strong>.<br>Only valid for 5 minutes. <br>Thank you for using VeriOne!</p>
      </body>
    </html>
    """.format(code=code)
    msg.attach(MIMEText(body, 'html'))

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as connection:
            connection.login(user=os.getenv('MAIL_USEREMAIL'), password=os.getenv('MAIL_PASSWORD'))
            connection.sendmail(from_addr="VeriOne",
                                to_addrs=to,
                                msg=msg.as_string())
        print("Email sent successfully!")
   
    except Exception as e:
        raise(e)