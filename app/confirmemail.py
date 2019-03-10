import sendgrid
from sendgrid.helpers.mail import *


def send_email(to, subject, body):
    sg = sendgrid.SendGridAPIClient(apikey='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')
    from_email = Email("admin@bloggercraft.com")
    to_email = Email(to)
    subject = subject
    content = Content("text/plain", body)
    mail = Mail(from_email, subject, to_email, content)
    response = sg.client.mail.send.post(request_body=mail.get())
    print(response.status_code)
    print(response.body)
    print(response.headers)