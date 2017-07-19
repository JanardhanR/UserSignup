import os
import jinja2
import webapp2
import string
import codecs
import re
import hashlib
import string
from google.appengine.ext import db



template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir), autoescape=True)



def hash_str(s):
    return hashlib.md5(s).hexdigest()

def make_secure_val(s):
    return "%s,%s" % (s,hash_str(s))

def check_secure_val(h):
    val = h.split(',')[0]
    if h == make_secure_val(val):
        return val

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class AuthCred():
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASSWORD = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    EMAIL = re.compile(r"^[\S]+@[\S]+.[\S]+$")

    def valid_username(self,username):
        return self.USER_RE.match(username)

    def valid_password(self,password):
        return self.PASSWORD.match(password)

    def is_match(self,password, verify_password):
        return password == verify_password

    def valid_email(self,email):
        return self.EMAIL.match(email)


class Welcome(Handler):
    def get(self):
        username = self.request.get("username")
        self.render("gooduser.html",username=username)

class SignUp(Handler):
    def get(self):
        self.render("usersignup.html")
    
    def post(self):
        # username = self.request.get("username")
        # password = self.request.get("password")
        # verify = self.request.get("verify")
        # email = self.request.get("email")
        self.resquest.cookie.get('username')
        usererror =""
        verifyerror =""
        emailerror =""
        passerror =""
        authcred = AuthCred()
        if not authcred.valid_username(username):
            usererror = "invalid user"
        elif not (authcred.valid_password(password) or authcred.valid_password(verify)):
            passerror = "invalid password"
            verify = ""
            password = ""
        elif not authcred.is_match(password, verify):
            verifyerror = "passwords dont match"
            verify = ""
            password = ""
        elif not authcred.valid_email(email):
            emailerror = "invalid email"
        else:
            self.redirect("/welcome?username="+username)
            return
        self.render("usersignup.html", username=username, password=password,verify=verify, email=email, usererror=usererror,passerror=passerror,verifyerror=verifyerror,emailerror=emailerror)


app = webapp2.WSGIApplication([('/', SignUp),('/welcome',Welcome)], debug=True)
