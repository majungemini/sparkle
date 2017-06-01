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
from models import Post, User, Comment
import hashutils
# from google.appengine.api import users
"""reuse default, login,signup,logout,hashutils codes from blog assignment"""
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)
# A list of paths that a user must be logged in to access
auth_paths = [
    '/blog/newpost'
]
class DefaultHandler(webapp2.RequestHandler):

    def get_posts(self, limit,offset):
        """get all posts ordered by creation date (descending)"""
        query = Post.all().order('-created')
        return query.fetch(limit=limit, offset=offset)

    def get_posts_by_user(self,user,limit,offset):
        """
            Get all posts by a specific user,ordered by creation date.
            The user parameter will be a User object,
        """
        query = Post.all().filter('author', user).order('-created')
        return query.fetch(limit=limit,offset=offset)

    def get_user_by_name(self,username):
        """Get a user object from the db, base on their username"""
        user = db.GqlQuery("SELECT * FROM User WHERE username = '%s'"% username)
        if user:
            return user.get()

    def login_user(self,user):
        """ Login a user specified by a User object user """
        user_id = user.key().id()
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
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name,cookie_val))

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

    def render_template(self, template_name, **context):
        if not self.user:
            me = "Welcome Visit"
        else:
            me= self.user.username
        t = jinja_env.get_template(template_name)
        response = t.render(me=me, **context)
        return response




class IndexHandler(DefaultHandler):


    def get(self):
        """ List all blog users """
        # user = users.get_current_user()
        # print(user)
        users = User.all()
        response = self.render_template('index.html', users=users)
        # t = jinja_env.get_template("index.html")
        # response = t.render(users = users, me=self.user)
        self.response.write(response)


offset=0
class MainPageHandler(DefaultHandler):
    page_size=5



    def get(self, username=""):
        """Fetch posts for all users,or a specific user,depending on request parameters"""
        if username:
            user = self.get_user_by_name(username)
            posts = self.get_posts_by_user(user, self.page_size, offset)
        else:
            posts = self.get_posts(self.page_size, offset)

        # t = jinja_env.get_template("mainpage.html")
        response = self.render_template('mainpage.html', posts=posts,
                                                        page_size=self.page_size,
                                                        username=username)
        # response = t.render(
        #                     posts=posts,
        #                     page_size=self.page_size,
        #                     username=username)
        self.response.out.write(response)
class UserViewHandler(DefaultHandler):
    page_size=10

    def get(self, username=""):
        """Fetch posts for all users,or a specific user,depending on request parameters"""
        if username:
            user = self.get_user_by_name(username)
            posts = self.get_posts_by_user(user, self.page_size, offset)
            counter = Post.all().filter('author', user).count()
        else:
            self.redirect('/login')
        # t = jinja_env.get_template("userview.html")
        response = self.render_template("userview.html", posts=posts,
                                                        page_size=self.page_size,
                                                        username=username,
                                                        counter=counter)
        # response = t.render(
        #                     posts=posts,
        #                     page_size=self.page_size,
        #                     username=username,
        #                     counter=counter)
        self.response.out.write(response)
class UserLookupHandler(DefaultHandler):
    def get(self, username=""):
        """Fetch posts for all users,or a specific user,depending on request parameters"""
        page_size=5
        if username:
            user = self.get_user_by_name(username)
            posts = self.get_posts_by_user(user, page_size, offset)
        else:
            self.redirect('/login')
        # t = jinja_env.get_template("userlookup.html")
        response = self.render_template("userlookup.html", posts=posts,
                                            page_size=page_size,
                                            username=username)
        self.response.out.write(response)


class NewPostHandler(DefaultHandler):
    def render_form(self, img="", body="", error=""):
        """ Render the new post form with or without an error, based on parameters """
        # t = jinja_env.get_template("newpost.html")
        response = self.render_template("newpost.html", img=img, body=body, error=error)
        self.response.out.write(response)

    def get(self):
        self.render_form()

    def post(self):
        """ Create a new blog post if possible. Otherwise, return with an error message """
        img = self.request.get("img")
        body = self.request.get("body")

        if img and body:

            # create a new Post object and store it in the database
            post = Post(
                img=img,
                body=body,
                author=self.user)
            post.put()

            # get the id of the new post, so we can render the post's page (via the permalink)
            id = post.key().id()
            self.redirect("/sparkle/%s" % id)
        else:
            error = "we need both a img and a body!"
            self.render_form(img, body, error)



class LoginHandler(DefaultHandler):
    def render_login_form(self, error=""):
        """Render the login form with or without an error,base on parameters """
        t = jinja_env.get_template("login.html")
        response = t.render(error=error)
        self.response.out.write(response)

    def get(self):
        self.render_login_form()



    def post(self):
        submitted_username = self.request.get("username")
        submitted_password = self.request.get("password")

        user = self.get_user_by_name(submitted_username)

        if not user:
            self.render_login_form(error="Invalid username")
        elif hashutils.valid_pw(submitted_username, submitted_password, user.pw_hash):
            self.login_user(user)
            self.redirect('/sparkle/%s' % submitted_username)
            # self.redirect('/mainpage?username=submitted_username')
        else:
            self.render_login_form(error="Invalid password")






class SignupHandler(DefaultHandler):

    def validate_username(self, username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        if USER_RE.match(username):
            return username
        else:
            return ""

    def validate_password(self, password):
        PWD_RE = re.compile(r"^.{3,20}$")
        if PWD_RE.match(password):
            return password
        else:
            return ""

    def validate_verify(self, password, verify):
        if password == verify:
            return verify

    def validate_email(self, email):

        # allow empty email field
        if not email:
            return ""

        EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
                            # (r"^[\S]+@[\S]+.[\S]+$")
        if EMAIL_RE.match(email):
            return email

    def get(self):
        t = jinja_env.get_template("signup.html")
        response = t.render(errors={})
        self.response.out.write(response)

    def post(self):
        """
            Validate submitted data, creating a new user if all fields are valid.
            If data doesn't validate, render the form again with an error.

            This code is essentially identical to the solution to the Signup portion
            of the Formation assignment. The main modification is that we are now
            able to create a new user object and store it when we have valid data.
        """

        submitted_username = self.request.get("username")
        submitted_password = self.request.get("password")
        submitted_verify = self.request.get("verify")
        submitted_email = self.request.get("email")

        username = self.validate_username(submitted_username)
        password = self.validate_password(submitted_password)
        verify = self.validate_verify(submitted_password, submitted_verify)
        email = self.validate_email(submitted_email)

        errors = {}
        existing_user = self.get_user_by_name(username)
        has_error = False

        if existing_user:
            errors['username_error'] = "A user with that username already exists"
            has_error = True
        elif (username and password and verify and (email is not None) ):

            # create new user object and store it in the database
            pw_hash = hashutils.make_pw_hash(username, password)
            user = User(username=username, pw_hash=pw_hash)
            user.put()

            # login our new user
            self.login_user(user)
        else:
            has_error = True

            if not username:
                errors['username_error'] = "That's not a valid username"

            if not password:
                errors['password_error'] = "That's not a valid password"

            if not verify:
                errors['verify_error'] = "Passwords don't match"

            if email is None:
                errors['email_error'] = "That's not a valid email"

        if has_error:
            t = jinja_env.get_template("signup.html")
            response = t.render(username=username, email=email, errors=errors)
            self.response.out.write(response)
        else:
            self.redirect('/mainpage')

class ErrorHandler(DefaultHandler):
    def get(self):
        self.response.write('ErrorHandler')


class ViewPostHandler(DefaultHandler):
    # """" temper used function """
    # def get(self):
    #     t = jinja_env.get_template("post.html")
    #     response = t.render()
    #     self.response.out.write(response)


    def get(self, id):
        """ Render a page with post determined by the id (via the URL/permalink) """

        post = Post.get_by_id(int(id))
        comments = db.GqlQuery("SELECT * FROM Comment WHERE postid = '%s'"% id)
        if post:
            # t = jinja_env.get_template("post.html")
            response = self.render_template("post.html",post=post,comments=comments)
        else:
            error = "there is no post with id %s" % id
            t = jinja_env.get_template("404.html")
            response = t.render(error=error,comments=comments)

        self.response.out.write(response)

    def post(self,id):
        post = Post.get_by_id(int(id))
        if post:
            submitted_comment = self.request.get("commentname")
            comment = Comment(
                    postid = id,
                    cmt= submitted_comment)
            comment.put()
            comments = db.GqlQuery("SELECT * FROM Comment WHERE postid = '%s'"% id)
            t = jinja_env.get_template("post.html")
            response = t.render(post=post,comments=comments)
            self.response.out.write(response)

class LogoutHandler(DefaultHandler):
    def get(self):
        self.logout_user()
        t = jinja_env.get_template("logout.html")
        response = t.render()
        self.response.out.write(response)

class Sparkle(DefaultHandler):
    def get(self):
        t = jinja_env.get_template("mainpage.html")
        response = t.render()
        self.response.out.write(response)

app = webapp2.WSGIApplication([
    ('/', IndexHandler),
    ('/mainpage',MainPageHandler),
    ('/newpost', NewPostHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/signup', SignupHandler),
    webapp2.Route('/sparkle/<id:\d+>', ViewPostHandler),
    webapp2.Route('/sparkle/<username:[a-zA-Z0-9_-]{3,20}>', UserViewHandler),
    webapp2.Route('/sparkle/<username:[a-zA-Z0-9_-]{3,20}>/favorite', UserLookupHandler),
    webapp2.Route('/sparkle/<username:[a-zA-Z0-9_-]{3,20}>/like', UserLookupHandler)
], debug=True)


auth_paths = [
    '/newpost'
]
