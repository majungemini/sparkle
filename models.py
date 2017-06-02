from google.appengine.ext import db

class User(db.Model):
    username = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

class Post(db.Model):
    img = db.LinkProperty(required = True)
    body = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    author = db.ReferenceProperty(User, required = True)

class Comment(db.Model):
    postid = db.StringProperty(required = True)
    cmt = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    
