#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2, jinja2, os, re
from google.appengine.ext import db
from models import Post, User


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)
# A list of paths that a user must be logged in to access
auth_paths = [
    '/blog/newpost'
]
class DefaultHandler(webapp2.RequestHandler):
    """retype from blog"""
    def get_post(self, limit,offset):
        """get all posts ordered by creation date (descending)"""
        query = Post.all().order('-created')
        return query.fetch(limit=limit, offset=offset)

    def get_posts_by_user(self,useroj,limit,offset):
        """
            Get all posts by a specific user,ordered by creation date.
            The user parameter will be a User object,
        """
        query = Post.all().filter('author', useroj).order('-created')
        return query.fetch(limit=limit,offset=offset)

    def get_user_by_name(self,username):
        """Get a user object from the db, base on their username"""
        useroj = db.GqlQuery("SELECT * FROM User WHERE username = '%s'"% username)
        if useroj:
            return useroj.get()

    def login_user(self,useroj):
        """ Login a user specified by a User object user """
        user_id = useroj.key().id()
        self.set_secure_cookie('user_id', str(user_id))

    def logout_user(self):
        """ Logout a user specified by a User object user """
        self.set_secure_cookie('user_id', '')

    def read_secure_cookie(self,name):
        cookie_val = self.request.cookies.get(name)
        if cookie_val:
            return hashutils.check_secure_val(cookie_val)

    def set_secure_cookie(self,name,val):
        cookie_val = hashutils.make_secure_val(val)
        self.request.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name,cookie_val))

    def initialize(self, *a, **kw):
        """
            A filter to restrict access to certain pages when not logged in.
            If the request path is in the global auth_paths list, then the user
            must be signed in to access the path/resource.
        """
        webapp2.RequestHandler.initialize(self,*a,**kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.get_by_id(int(uid))

        if not self.user and self.request.path in auth_paths:
            self.redirect('/login')

class IndexHandler(DefaultHandler):

    def get(self):
        """ List all blog users """
        users = User.all()
        # response = self.render_template('index.html', users=users)
        t = jinja_env.get_template("mainpage.html")
        response = t.render(users = users)
        self.response.write(response)

class MainPageHandler(DefaultHandler):
    story_size=5
    offset=0
    def get(self, username=""):
        """Fetch posts for all users,or a specific user,depending on request parameters"""
        if username:
            user = self.get_user_by_name(username)
            posts =self.get_posts_by_user(user, self.page_size,offset)
        else:
            posts = self.get_posts(self.page_size,offset)

        t = jinja_env.get_template("mainpage")
        response = t.render(
                            posts=posts,

                            page_size=self.page_size,
                            
                            username=username)
        self.response.out.write(response)

class NewPostHandler(DefaultHandler):
    def get(self):
        self.response.write('NewPostHandler!')
class LoginHandler(DefaultHandler):
    def get(self):
        self.response.write('LoginHandler!')
class LogoutHandler(DefaultHandler):
    def get(self):
        self.response.write('LogoutHandler!')
class SignupHandler(DefaultHandler):
    def get(self):
        self.response.write('SignupHandler!')
class ErrorHandler(DefaultHandler):
    def get(self):
        self.response.write('ErrorHandler')





class Sparkle(webapp2.RequestHandler):
    def get(self):
        self.response.write('Hello world!')

app = webapp2.WSGIApplication([
    ('/', IndexHandler),
    ('/mainpage',Sparkle),
    ('/newpost', NewPostHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/signup', SignupHandler)
], debug=True)
