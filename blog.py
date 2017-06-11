import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'imagination'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    user    = db.StringProperty(required = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class Comment(db.Model):
    content = db.TextProperty(required = True)
    user    = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", c = self)

      
class Like(db.Model):
    user = db.StringProperty(required = True)
    like = db.IntegerProperty(required = True)
    comment = db.BooleanProperty(required = True)

#displays all blog posts
    
class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts)

# Displays a post in the blog, and allows users to post a comment on the respective post        
        
class PostPage(BlogHandler):
  def get(self, post_id, error):

    error_num = self.request.get('error')

    if error_num:
        error_num = int(error_num)

    post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
    post = db.get(post_key)

    if not post:
      self.error(404)
      return

    comments = db.Query(Comment)
    comments.ancestor(post_key).order('created')
    error = ""

    likes = db.Query(Like)
    p_likes=likes.ancestor(post_key).filter('comment =', False).filter('like =', 1).count()
    likes = db.Query(Like)
    p_dislikes=likes.ancestor(post_key).filter('comment =', False).filter('like =', -1).count()

    comment_likes = []
    comment_dislikes = []
    for c in comments:
        likes = db.Query(Like)
        comment_likes.append(likes.ancestor(c).filter('like =', 1).count())
        likes = db.Query(Like)
        comment_dislikes.append(likes.ancestor(c).filter('like =', -1).count())

    if error_num == 2:
      error = "You cannot like your own posts"
    elif error_num == 3:
      error = "You can only edit your own content"
    elif error_num == 4:
      error = "You can only delete your own posts"

    self.render("permalink.html", post = post, comments = comments,
                p_likes=p_likes, p_dislikes=p_dislikes, c_likes=comment_likes, c_dislikes=comment_dislikes, error=error)

  def post(self, post_id, error):
    if not self.user:
      self.redirect('/login')
    else:
      key = db.Key.from_path('Post', int(post_id), parent=blog_key())

      comment = self.request.get('comment')

      if comment:
        c = Comment(parent = key, content = comment, user=self.user.name)
        c.put()
        self.redirect('/blog/%s' % post_id)

# allows for editing pages if there is no page with an id matching the one given in the URL
# the function returns a 404, otherwise it verifies the user is the same as the original poster
# and either allows them to edit the page or redirects them to the post's page
        
class EditPage(BlogHandler):
  def get(self, post_id):
    key = db.Key.from_path('Post', int(post_id), parent=blog_key())
    post = db.get(key)

    if not post:
      self.error(404)
      return
    elif post.user == self.user.name:
      self.render("editpage.html", p=post, user=self.user.name)
    else:
      self.redirect("/blog/%s?error=3" % post.key().id())

  def post(self, post_id):
    key = db.Key.from_path('Post', int(post_id), parent=blog_key())
    post = db.get(key)

    if not post:
      self.error(404)
      return
    elif post.user != self.user.name:
      self.redirect("/blog/%s?error=3" % post.key().id())
      return
      
    content = self.request.get('content')

    if content:
      post.content = content
      post.put()
      self.redirect('/blog/%s' % str(post.key().id()))
    else:
      self.render("editpage.html", p=post, user=self.user.name)

# Allows a user to delete their own posts      
      
class DeletePage(BlogHandler):
    def post(self, post_id):
        if not self.user:
          self.redirect('/login')
        else:
          key = db.Key.from_path('Post', int(post_id), parent=blog_key())
          post = db.get(key)

          if not post:
            self.error(404)
            return

          if self.user.name == post.user:
            db.delete(post)
            self.redirect('/blog')

          else:
            self.redirect('/blog/%s?error=4' % key.id())

# Allows a user to delete their own comments            
            
class DeleteComment(BlogHandler):
    def post(self, i):
      if not self.user:
        self.redirect('/login')
      else:
        ids = i.split(',')
        p = db.Key.from_path('Post', int(ids[0]), parent=blog_key())
        key = db.Key.from_path('Comment', int(ids[1]), parent=p)

        comment = db.get(key)

        if not comment:
          self.error(404)
          return

        if self.user.name == comment.user:
          db.delete(comment)
          self.redirect('/blog/%s' % p.id())
        else:
          self.redirect('/blog/%s?error=4' % p.id())

# Allows for editing comments if there is no comment with an id matching the one given in the URL
# the function returns a 404, otherwise it verifies the user is the same as the original poster
# and either allows them to edit the comment or redirects them to the comment's post's page
          
class EditComment(BlogHandler):
    def get(self, comment_id, i):
      post_id = self.request.get('post_id')

      p = db.Key.from_path('Post', int(post_id), parent=blog_key())
      key = db.Key.from_path('Comment', int(comment_id), parent=p)

      comment = db.get(key)

      if not comment:
        self.error(404)
        return
      elif comment.user == self.user.name:
        self.render("editcomment.html", c=comment, user=self.user.name)
      else:
        self.redirect("/blog/%s?error=3" % comment.key().parent().id())

    def post(self, i):
      ids = i.split(',')
      p = db.Key.from_path('Post', int(ids[0]), parent=blog_key())
      key = db.Key.from_path('Comment', int(ids[1]), parent=p)

      comment = db.get(key)

      if not comment:
        self.error(404)
        return
      elif comment.user != self.user.name:
        self.redirect("/blog/%s?error=3" % post.key().id())
        return
      
      content = self.request.get('content')

      if content:
        comment.content = content
        comment.put()

        self.redirect('/blog/%s' % comment.key().parent().id())
      else:
        self.render("editcomment.html", c=comment, user=self.user.name)

# Allows a user to like a post. If the user has already liked the comment 
# it allows them to unlike, or dislike the comment. If the user tries to like their own
# post it redirects them and displays an error letting them know that is not allowed                
        
class LikePage(BlogHandler):
  def post(self, i):
    if not self.user:
      self.redirect('/login')
    else:
      changed = False
      ids = i.split(',')

      post_id = ids[0]
      val = int(ids[1])

      key = db.Key.from_path('Post', int(post_id), parent=blog_key())
      post = db.get(key)

      if not post:
        self.error(404)
        return

      if self.user.name == post.user:
        self.redirect('/blog/%s?error=2' % key.id())
        return

      q = db.Query(Like)
      q.ancestor(key).filter('comment =', False)

      for like in q:
        if like.user == self.user.name:
          if like.like==val:
            like.like = 0
            like.put()
            changed = True
          else:
            like.like=val
            like.put()
            changed = True

      if not changed:
        l = Like(parent=key, like=val,user=self.user.name, comment=False)
        l.put()
        self.redirect('/blog/%s' % str(post.key().id()))
      else:
        self.redirect('/blog/%s' % str(post.key().id()))


# Allows a user to like a comment. If the user has already liked the comment 
# it allows them to unlike, or dislike the comment. If the user tries like their own
# comment it redirects them and displays an error letting them know that is not allowed
        
class LikeComment(BlogHandler):
  def post(self, i):
    if not self.user:
      self.redirect('/login')
    else:
      changed = False

      ids = i.split(',')
      p = db.Key.from_path('Post', int(ids[0]), parent=blog_key())
      key = db.Key.from_path('Comment', int(ids[1]), parent=p)
      val = int(ids[2])

      comment = db.get(key)

      if not comment:
        self.error(404)
        return

      if self.user.name == comment.user:
        self.redirect('/blog/%s?error=2' % p.id())
        return

      q = db.Query(Like)
      q.ancestor(key)

      for like in q:
        if like.user == self.user.name:
          if like.like==val:
            like.like = 0
            like.put()
            changed = True
          else:
            like.like=val
            like.put()
            changed = True


      if not changed:
        l = Like(parent=comment, like=val, user=self.user.name, comment=True)
        l.put()
        self.redirect('/blog/%s' % comment.key().parent().id())
      else:
        self.redirect('/blog/%s' % comment.key().parent().id())

# allows a user to create a new post, as long as they are logged in
class NewPost(BlogHandler):
  def get(self):
    if self.user:
      self.render("newpost.html")
    else:
      self.redirect("/login")

  def post(self):
    if not self.user:
      self.redirect('/blog')
    else:

      subject = self.request.get('subject')
      content = self.request.get('content')

      if subject and content:
        p = Post(parent = blog_key(), subject = subject, content = content, user=self.user.name)
        p.put()
        self.redirect('/blog/%s' % str(p.key().id()))
      else:
        error = "subject and content, please!"
        self.render("newpost.html", subject=subject, content=content, error=error)





USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
  return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
  return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
  return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
  def get(self):
    self.render("signup.html")

  def post(self):
    have_error = False
    self.username = self.request.get('user')
    self.password = self.request.get('password')
    self.verify = self.request.get('verify')
    self.email = self.request.get('email')

    params = dict(username = self.username,
                  email = self.email)

    if not valid_username(self.username):
      params['user_error'] = "That's like not a valid username."
      have_error = True

    if not valid_password(self.password):
      params['pass_error'] = "That wasn't a valid password."
      have_error = True
    elif self.password != self.verify:
      params['ver_error'] = "Your passwords didn't match."
      have_error = True

    if not valid_email(self.email):
      params['email_error'] = "That's not a valid email."
      have_error = True

    if have_error:
      self.render('signup.html', **params)
    else:
      self.done()

  def done(self, *a, **kw):
    raise NotImplementedError


class Register(Signup):
  def done(self):
        #make sure the user doesn't already exist
    u = User.by_name(self.username)
    if u:
      msg = 'That user already exists.'
      self.render('signup.html', error_username = msg)
    else:
      u = User.register(self.username, self.password, self.email)
      u.put()

    self.login(u)
    self.redirect('/blog')

class Login(BlogHandler):
  def get(self):
    self.render('login.html')

  def post(self):
    username = self.request.get('user')
    password = self.request.get('password')

    u = User.login(username, password)
    if u:
      self.login(u)
      self.redirect('/blog')
    else:
      msg = 'Invalid login'
      self.render('login.html', error = msg)

class Logout(BlogHandler):
  def get(self):
    self.logout()
    self.redirect('/blog')


app = webapp2.WSGIApplication([('/blog/?', BlogFront),
                               ('/blog/([0-9]+(\?error=[0-9]+)?)', PostPage),
                               ('/blog/editpage/([0-9]+)', EditPage),
                               ('/blog/likepage/([0-9]+,-?1)', LikePage),
                               ('/blog/deletepage/([0-9]+)', DeletePage),
                               ('/blog/deletecomment/([0-9]+,[0-9]+)', DeleteComment),
                               ('/blog/likecomment/([0-9]+,[0-9]+,-?1)', LikeComment),
                               ('/blog/editcomment/([0-9]+(\?post_id=[0-9]+)?)', EditComment),
                               ('/blog/editcomment/([0-9]+,[0-9]+)', EditComment),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
