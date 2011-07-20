import logging, email
from google.appengine.ext import webapp,db
from google.appengine.ext.webapp.mail_handlers import InboundMailHandler 
from google.appengine.ext.webapp.util import run_wsgi_app

class IncomingEmail(db.Model):
    subject  = db.StringProperty()
    sender   = db.StringProperty()
    to       = db.StringProperty()
    date     = db.StringProperty()
    body     = db.TextProperty()
    original = db.TextProperty()

class LogSenderHandler(InboundMailHandler):
    def receive(self, mail_message):
        email = IncomingEmail(
            subject     = mail_message.subject,
            sender      = mail_message.sender,
            to          = mail_message.to,
            date        = mail_message.date,
            body        = str([body.decode() for type, body in mail_message.bodies('text/plain') ]),
            original    = mail_message.original.as_string())
        email.put()
        logging.info("Received an email. " + str(mail_message.original))
        
application = webapp.WSGIApplication([LogSenderHandler.mapping()])

def main():
    run_wsgi_app(application)

if __name__ == '__main__':
    main()