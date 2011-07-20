from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app

class MainPage(webapp.RequestHandler):
    def get(self):
        user = users.get_current_user()
        if user:
            print "Welcome, %s!" % user.nickname()
            if users.is_current_user_admin():
                print "<a href=\"#\">Go to admin area</a>"
        else:
            self.redirect(users.create_login_url(self.request.uri))

application = webapp.WSGIApplication(
                                     [('/admin', MainPage)],
                                     debug=True)

def main():
    run_wsgi_app(application)

if __name__ == "__main__":
    main()
