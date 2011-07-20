#!/usr/bin/env python

import logging
import os
import urllib
import re
import hashlib
import pickle
from random import random

from google.appengine.ext import webapp,db
from google.appengine.ext.webapp import util
from google.appengine.ext.webapp import template
from google.appengine.api import urlfetch,mail

from gaesessions import get_current_session
from django.utils import simplejson as json

import strings

ENVIRONMENT = "prod"

if ENVIRONMENT == "stage":
    CLIENT_ID = '57417'
    CLIENT_SECRET = '3436239931'
    ACCESS_TOKEN = '2f726a0a9b9a4ec5770165e9c851b8388e146f437237b394f7dcbb086823e43d'
    WEPAY = 'https://stage.wepay.com/v2'
elif ENVIRONMENT == "vm":
    CLIENT_ID = '3552'
    CLIENT_SECRET = '98f943401f'
    ACCESS_TOKEN = 'baaa941e1209ae33f5c8d67d867ce8800456fd156d3c2249e0dd3c705aed4be4'
    WEPAY = 'http://vm.wepay.com/v2'
elif ENVIRONMENT == "prod":
    CLIENT_ID = '122204'
    CLIENT_SECRET = 'c66373c325'
    ACCESS_TOKEN = '644b036a255dfd2851f4d7e4b2889dea34329ffea2a567fe82e19478afe71c75'
    WEPAY = 'https://www.wepay.com/v2'
    
APP_FEE = '0.10'
CANCEL_STATES = ('new', 'authorized', 'reserved')
MAX_BET = 1000.0
HOST_URL = '' # gets populated in controller init

class WePay(object):
    token = None
    def call(self, uri, params={}, token=None):
        """Calls wepay.com/uri with params and returns the json response as a python dict. Will use post if token is set."""
        # TODO: uri and url are backwards. turn around now, switch. turn it over now
        url = WEPAY + "/" + uri
        payload = ''
        if self.token or token:
            headers = {
                'Authorization': 'Bearer ' + (token if token else self.token),
                'Content-Type' : 'application/json'
            }
            if params:
                payload = json.dumps(params)
            method = urlfetch.POST
        else:
            url += "?" + urllib.urlencode(params)
            headers = {}
            method = urlfetch.GET
        
        logging.debug('calling urlfetch: ' + url + ' payload: ' + payload + ' headers: ' +  str(headers))
        response = urlfetch.fetch(url, payload=payload, headers=headers, method=method)
        if (response.status_code == 200):
            return json.loads(response.content)
        else:
            logging.error("urlfetch error: " + response.content)
            return None

class User(db.Model):
    wepay_id        = db.StringProperty()
    account_id      = db.StringProperty()
    access_token    = db.StringProperty()
    message         = db.StringProperty(default="")
    user_info       = db.BlobProperty(default=None)
    
    def get(wepay_id):
        """get a user based on wepay_id"""
        # note:  u + wepay_id is the db key name just as a way to distinguish it from the field
        return db.get(db.Key.from_path('User', "u" + wepay_id))
    get = staticmethod(get)
    
    def get_user_info(self):
        if not self.user_info:
            wepay = WePay()
            user_info = wepay.call('user', token=self.access_token)
            if not user_info:
                logging.error("couldn't get user info for user key " + str(self.key()))
                return
            self.user_info = pickle.dumps(user_info)
            self.put()
        else:
            user_info = pickle.loads(self.user_info)
        return user_info

    def shortname(self):
        """returns first name last initial"""
        user_info = self.get_user_info()
        return user_info['first_name'] + " " + user_info['last_name'][:1] + "."
    
    def longname(self):
        """returns first and last name"""
        user_info = self.get_user_info()
        return user_info['first_name'] + " " + user_info['last_name']

class Bet(db.Model):
    user_id             = db.StringProperty()   # user who made the bet
    chump_id            = db.StringProperty()   # id of the bet accepter, empty until accepted
    amount              = db.FloatProperty()
    users_checkout_id   = db.IntegerProperty(default=None)
    chumps_checkout_id  = db.IntegerProperty(default=None)
    state               = db.StringProperty(default="new", choices=("new", "ready", "unsettled", "done"))
    result              = db.StringProperty(default=None, choices=(None, "user_won", "chump_won", "cancelled"))
    arbiter             = db.StringProperty(default=None)
    
    def email_arbiter(self):
        """send the email to the arbiter to settle the bet"""
        user = User.get(self.user_id)
        chump = User.get(self.chump_id)
        
        user_name = user.longname()
        chump_name = chump.longname()
        
        mail.send_mail(sender="MONEYtoWASTE <betgods@moneytowaste.appspotmail.com>",
                      to=self.arbiter,
                      subject=user_name + " has chosen you to settle a bet",
                      body=strings.ARBITER_MESSAGE % { 'user'   : user_name,
                                                       'chump'  : chump_name,
                                                       'user_wins' : self.settle_link(user_wins=True),
                                                       'chump_wins' : self.settle_link(user_wins=False),
                                                       'amount' : self.amount })
    
    def settle(self, user_wins):
        """attempts to call wepay to officially settle the bet. 
        cancels user's bet if user_wins is true. otherwise, cancels
        the chumps bet. attempts to capture loser's bet. returns true on success"""
        user = User.get(self.user_id)
        chump = User.get(self.chump_id)
        if not chump or not user or not self.users_checkout_id or not self.chumps_checkout_id:
            logging.error("tried to settle a bet that wasn't ready")
            return
        if user_wins:
            checkout_id = self.users_checkout_id
            token = user.access_token
            loser_checkout = self.chumps_checkout_id
            loser_token = chump.access_token
        else:
            checkout_id = self.chumps_checkout_id
            token = chump.access_token
            loser_checkout = self.users_checkout_id
            loser_token = user.access_token
        params = {
            'checkout_id'   : checkout_id,
            'cancel_reason' : "returning the winner's bet"
        }
        wepay = WePay()
        cancel_response = wepay.call('checkout/cancel', params, token=token)
        
        if cancel_response:
            self.state = "done"
            self.result = ("user_won" if user_wins else "chump_won")
            self.put()
            
            # check to see if we can capture right away
            checkout = wepay.call('checkout', { 'checkout_id' : loser_checkout }, token=loser_token)
            if checkout['state'].lower() == "reserved":                    
                capture_response = wepay.call('checkout/capture', { 'checkout_id' : loser_checkout }, token=loser_token)
                if not capture_response:
                    logging.error('couldn\'t capture checkout_id ' + str(checkout_id))

            return True
        else:
            logging.error('error settling bet with users_checkout_id as ' + str(self.users_checkout_id) + str(cancel_response))
    
    def garbled_arbiter(self):
        """returns the arbiter's email slightly garbled"""
        return self.arbiter.replace("@", " at ")[:-4]
    
    def user(self):
        """returns the user"""
        return User.get(self.user_id)
    
    def chump(self):
        """returns chump"""
        return User.get(self.chump_id)
    
    # hash functions for secret links.
    # hash is based on opponent ids because the user shouldn't have any way of knowing them
    def user_hash(self):
        return hashlib.sha224("peanuts" + str(self.chumps_checkout_id) + str(self.chump_id) + str(self.amount)).hexdigest()
    def chump_hash(self):
        return hashlib.sha224("grapes" + str(self.users_checkout_id) + str(self.user_id) + str(self.amount)).hexdigest()
    
    def settle_link(self, user_wins):
        url = HOST_URL + "/settle?b=" + str(self.key())
        if user_wins:
            url += "&w=u&h=" + self.user_hash()
        else:
            url += "&w=c&h=" + self.chump_hash()
        return url
    

class Controller(webapp.RequestHandler):
    def init(self, anonymous=False):
        """Sets up sessions and other objects. Returns True if logged in False otherwise."""
        global HOST_URL
        HOST_URL = self.request.host_url
        
        self.session = get_current_session()
        self.anonymous = anonymous
        self.wepay = WePay()
        self.user = None
        if not self.session.has_key('message'): self.session['message'] = ''
        if self.session.has_key('token'):
            self.user_id = str(self.session['user_id'])
            self.wepay.token = self.session['token']
            self.user = User.get(self.user_id)
            if self.user:
                if self.user.message:
                    self.session['message'] += ' ' + self.user.message
                    self.user.message = ''
                    self.user.put()
                if self.user.account_id:
                    self.user.account = {}
                    self.user.account['balance'] = self.wepay.call('account/balance', { 'account_id': self.user.account_id })
                    self.user.account['info'] = self.wepay.call('account', { 'account_id': self.user.account_id })
                return True
            else:
                # bad session or something. stops the redirect loop.
                self.redirect("/logout")
                return False
        
        if not self.anonymous: self.redirect("/")
        return False

    def render(self, file, vars = {}):
        """Renders the template file with the passed in vars"""
        tpath = os.path.join(os.path.dirname(__file__), 'templates', file)
        fpath = os.path.join(os.path.dirname(__file__), 'templates', 'frame.html')
        fv = {  'current_page'  : file,
                'user'          : self.user,
                'content'       : template.render(tpath, vars),
                'message'       : self.session['message'] }
        if self.session['message']: self.session['message'] = ''
        self.response.out.write(template.render(fpath, fv))
    
    def redirect(self, uri, message=None, permanent=False):
        if message:
            session = get_current_session()
            session['message'] = message
        super(Controller, self).redirect(uri, permanent)
            

class Login(Controller):
    def get(self):
        session = get_current_session()
        if session.has_key('token'): # already logged in
            self.redirect("/home")
            return
        code = self.request.get('code')
        if code:
            self.wepay = WePay()
            params = {
                'client_id'     : CLIENT_ID,
                'redirect_uri'  : self.request.host_url,
                'client_secret' : CLIENT_SECRET,
                'code'          : code
            }
            result = self.wepay.call('oauth2/token', params)
            
            if result:
                logging.debug("User " + str(result['user_id']) + " logged into wepay and got us an access token.")
                
                if session.is_active():
                    session.terminate()
                session['user_id'] = str(result['user_id'])
                session['token'] = result['access_token']
                
                self.init() # call init to set up user object
                if not self.user: # we haven't made the user yet
                    self.user = User(key_name="u" + str(self.user_id), wepay_id=str(self.user_id))
                    self.user.put()
                    logging.info("Created a user with wepay_id " + self.user_id)
                self.user.access_token = session['token']
                self.user.put()
                
                # everything worked, lets go home!
                self.redirect("/home")
            else:
                self.response.out.write("oops. something went wrong. <a href=\"/\">ugh</a>")
        else:
            self.init(anonymous=True)
            vars = {
                'url': WEPAY + "/oauth2/authorize?client_id="+CLIENT_ID+"&redirect_uri="+self.request.host_url+"&scope=manage_accounts,collect_payments,view_balance,view_user"
            }
            self.render('index.html', vars)

class Logout(webapp.RequestHandler):
    def get(self):
        session = get_current_session()
        if session.is_active():
            session.terminate()
        self.redirect("/")
    
class Home(Controller):
    def get(self):
        if self.init():
            ready_bets = Bet.all().filter("user_id", self.user_id).filter("state", "ready")
            waitingon_bets = Bet.all().filter("chump_id", self.user_id).filter("state", "ready")
            open_bets = Bet.all().filter("user_id", self.user_id).filter("state", "new")
            avail_bets = Bet.all().filter("user_id !=", self.user_id).filter("state", "new")
            unsettled_as_user = Bet.all().filter("user_id", self.user_id).filter("arbiter !=", None).filter("state", "unsettled")
            unsettled_as_chump = Bet.all().filter("chump_id", self.user_id).filter("arbiter !=", None).filter("state", "unsettled")
            vars = {
                'user'               : self.user,
                'ready_bets'         : ready_bets if ready_bets.count(1) else None,
                'waitingon_bets'     : waitingon_bets if waitingon_bets.count(1) else None,
                'open_bets'          : open_bets,
                'avail_bets'         : avail_bets,
                'unsettled_as_user'  : unsettled_as_user if unsettled_as_user.count(1) else None,
                'unsettled_as_chump' : unsettled_as_chump if unsettled_as_chump.count(1) else None
            }
            self.render('home.html', vars)

class CreateAccount(Controller):
    def get(self):
        if self.init():
            if self.user.account_id and self.user.account['info']:
                # we already have an account record for this user and it's still valid (account got set)
                self.redirect('/home')
                return
            params = {
                'name'          : 'MONEYtoWASTE Winnings',
                'description'   : 'all the money made from bets',
                'image_uri'     : 'http://moneytowaste.appspot.com/s/img/mtw_logo.png'
            }
            result = self.wepay.call('account/create', params)
            if result:
                self.user.account_id = str(result['account_id'])
                self.user.put()
                logging.info('Created a new account for user with id ' + self.user_id)
                self.redirect('/home')
            else:
                self.render('whatever.html', { 'whatever': "awwww, shit. it broke. <a href=\"/\">ugh</a>" } )

class MakeABet(Controller):
    def get(self):
        if self.init():
            self.render('makeabet.html')
    def post(self):
        if self.init():
            try:
                bet_amount = float(self.request.get('amount'))
            except ValueError, e:
                bet_amount = False
                logging.info("Invalid bet amount: " + str(e))
                self.redirect('/bet', "my machine didn't like what you put in the box.")
                return
            if bet_amount > MAX_BET:    
                self.redirect('/bet', "you can't bet more than " + str(MAX_BET))
                return
            if bet_amount:
                bet = Bet(user_id=self.user_id, amount=bet_amount)
                arbiter = self.request.get('arbiter')
                if arbiter:
                    # email address check
                    if not re.match("[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}", arbiter, re.I):
                        self.redirect('/bet', "that doesn't look like a real email address.")
                        return
                    bet.arbiter = arbiter
                bet.put()
                logging.info("Bet created by " + self.user_id + " for $" + str(bet_amount))
                self.redirect('/home') # done or empty post

class AcceptBet(Controller):
    def get(self):
        if self.init():
            bet_key = self.request.get('b')
            # if better_mode is set then the current user created the bet and is now paying
            better_mode = self.request.get('m')
            bet = db.get(db.Key(bet_key))
            
            if not bet:
                self.redirect(self.request.referrer, "couldn't find that bet")
                return
            
            # bet has been removed
            if bet.state in ("done","unsettled"):
                self.redirect(self.request.referrer, "sorry dude, that bet is gone")
                return
            # bet made by the user
            if not better_mode and bet.user_id == self.user_id:
                self.redirect(self.request.referrer, "wtf? you can't bet against yourself.")
                return
            # bet has already been accepted
            if not better_mode and bet.state != "new":
                self.redirect(self.request.referrer, "somebody already called that bet.")
                return
            
            # better_mode
            # bet hasn't been accepted by a chump
            if better_mode and bet.state != "ready":
                self.redirect(self.request.referrer, "you're bet isn't ready yet")
                return
            # bet not owned by the current user
            if better_mode and bet.user_id != self.user_id:
                self.redirect(self.request.referrer, "uuuuhhh, you didn't make this bet")
                return
            
            if better_mode:
                user = User.get(bet.chump_id)
            else:
                user = User.get(bet.user_id)
            params = {
                'account_id'        : user.account_id ,
                'short_description' : "bettin' some money",
                'type'              : "PERSONAL",
                'amount'            : bet.amount,
                'app_fee'           : APP_FEE,
                'auto_capture'      : 0,
                'redirect_uri'      : self.request.host_url + "/callback",
                'callback_uri'      : self.request.host_url + "/callback"
            }
            result = self.wepay.call('checkout/create', params, token=user.access_token)
            if result:
                if better_mode:
                    bet.users_checkout_id = result['checkout_id']
                else:
                    bet.chump_id = self.user_id
                    bet.chumps_checkout_id = result['checkout_id']
                bet.put()
                self.redirect(result['checkout_uri']);
            else:
                logging.error('failed to create a checkout')
                self.render('whatever.html', { 'whatever': "awwww, shit. it broke. <a href=\"/\">ugh</a>" })

class SettleBet(Controller):
    def get(self):
        self.init(anonymous=True)
        bet_key = self.request.get('b')
        winner = self.request.get('w')
        bet_hash = self.request.get('h')
        bet = db.get(db.Key(bet_key))
        
        if not bet or not winner or not bet_hash or bet.state != "unsettled":
            self.redirect("/", "something went wrong.")
            return
        
        user = User.get(bet.user_id)
        chump = User.get(bet.chump_id)
        
        if winner == "u" and bet_hash == bet.user_hash():
            settle_result = bet.settle(user_wins=True)
            if settle_result:
                user.message += " you won $%.2f off of %s!!! nice work" % (bet.amount, chump.longname())
                user.put()
                chump.message += " you lost $%.2f to %s. tough bananas." % (bet.amount, user.longname())
                chump.put()
                self.render('whatever.html', { 'whatever': "you just awarded %s $%.2f!! what a pal" % (user.longname(), bet.amount) } )
                return
            else:
                self.redirect("/", "something went wrong.")
                return
        elif winner == "c" and bet_hash == bet.chump_hash():
            settle_result = bet.settle(user_wins=False)
            if settle_result:
                user.message += " you lost $%.2f to %s. boy, that sucks" % (bet.amount, chump.longname())
                user.put()
                chump.message += " you won $%.2f of %s!! awwwww yeeeeeee." % (bet.amount, user.longname())
                chump.put()
                self.render('whatever.html', { 'whatever': "you just awarded %s $%.2f!! what a pal" % (chump.longname(), bet.amount) } )
                return
            else:
                self.redirect("/", "something went wrong.")
                return
        else:
            self.redirect("/", "huh?! you can't settle that bet")
            return

class Cancel(Controller):
    def get(self):
        if self.init():
            bet_key = self.request.get('b')
            bet = db.get(db.Key(bet_key))
            
            if bet.chump_id == self.user_id or bet.user_id == self.user_id:
                if bet.state == "new":
                    bet.state = "done"
                    bet.result = "cancelled"
                    bet.put()
                    self.redirect("/home", "your bet has been taken down. i hope you're just deciding to make it bigger.")
                    return
                elif bet.state == "ready":
                    checkout = self.wepay.call('checkout', { 'checkout_id' : bet.chumps_checkout_id })
                    if checkout and checkout['state'] in CANCEL_STATES:
                        params = {
                            'checkout_id'   : bet.chumps_checkout_id,
                            'cancel_reason' : 'chump wussed out and cancelled their bet'
                        }
                        cancel_response = self.wepay.call('checkout/cancel', params)
                        
                        if cancel_response and cancel_response['checkout_id'] == bet.chumps_checkout_id:
                            bet.state = "done"
                            bet.result = "cancelled"
                            bet.put()
                            self.redirect("/home", "you just took your bet back, you wussy.")
                            # TODO: alert user that they got janked
                            return
                        else:
                            logging.error(str(cancel_response))
                    else:
                        logging.error(str(checkout))
            self.redirect("/home", "you tried to cancel a bet but it didn't work. tough luck.")

class Callback(Controller):
    def get(self):
        self.init(anonymous=True)
        
        if self.request.get('checkout_id') and self.request.get('checkout_id').isdigit():
            # returning from checkout
            
            checkout_id = int(self.request.get('checkout_id'))
            bet = Bet.all().filter('chumps_checkout_id', checkout_id).get()
            if bet:
                # chump just accepted a bet
                bet.state = "ready"
                bet.put()
                self.redirect("/home", "you accepted a bet!! good job!!")
                return
            
            bet = Bet.all().filter('users_checkout_id', checkout_id).get()
            if not bet:
                self.redirect("/home", "coulnd't find your bet")
                return
            
            # user just finished checkout, bet is now unsettled
            bet.state = "unsettled"
            bet.put()
            if bet.arbiter:
                bet.email_arbiter()
                self.redirect("/home", "your arbiter (%s) has been sent an email to settle the bet!" % bet.arbiter)
                return
            else:
                r = random()
                # current user will always be user here.
                chump = bet.chump()
                user = bet.user()
                if r > 0.5:
                    settle_result = bet.settle(user_wins=True)
                    if settle_result:
                        chump.message += " you lost $%.2f to %s. good thing money can't buy happiness." % (bet.amount, user.longname())
                        chump.put()
                        self.redirect("/home", "you just won $%.2f!!! awesome!!" % bet.amount)
                        return
                    else:
                        self.redirect("/home", "uhhh.. sorry. something went wrong.")
                        return
                else:
                    settle_result = bet.settle(user_wins=False)
                    if settle_result:
                        chump.message += " you won $%.2f off of %s!! happy birthday!" % (bet.amount, user.longname())
                        chump.put()
                        self.redirect("/home", "you just lost $%.2f. them's the breaks." % bet.amount)
                        return
                    else:
                        self.redirect("/home", "uhhh.. sorry. something went wrong.")
                        return
        
        if self.request.get('error'):
            error = self.request.get('error_description')
            logging.error("wepay error: " + error)
            self.render('whatever.html', { 'whatever': "<strong>WePay error:</strong> " + error } )
        else:    
            self.render('whatever.html', { 'whatever': self.request } )
        self.redirect("/home")
    def post(self):
        if self.request.get('checkout_id') and self.request.get('checkout_id').isdigit():
            checkout_id =  int(self.request.get('checkout_id'))
            
            userbet = Bet.all().filter('users_checkout_id', checkout_id).get()
            chumpbet = Bet.all().filter('chumps_checkout_id', checkout_id).get()
            
            if userbet:
                bet = userbet
                user = User.get(bet.user_id)
            elif chumpbet:    
                bet = chumpbet
                user = User.get(bet.chump_id)
            else:
                logging.error('couldnt find a bet with checkout_id ' + str(checkout_id))
                return
            
            wepay = WePay()
            checkout = wepay.call('checkout', { 'checkout_id' : checkout_id }, token=user.access_token)
            logging.debug('received IPN from wepay. checkout data: ' + str(checkout))
            if checkout['state'].lower() == "reserved":
                if bet and bet.state == "done":
                    capture_response = wepay.call('checkout/capture', { 'checkout_id' : checkout_id }, token=user.access_token)
                    if not capture_response:
                        logging.error('couldn\'t capture checkout_id ' + str(checkout_id))

class Wtf(Controller):
    def get(self):
        self.init(anonymous=True)
        self.render('wtf.html')

class Whatever(Controller):
    def get(self):
        self.init(anonymous=True)
        self.render('whatever.html', { 'whatever': 'hi' })

application = webapp.WSGIApplication([  ('/', Login),
                                        ('/home', Home),
                                        ('/logout', Logout),
                                        ('/create_account', CreateAccount),
                                        ('/callback', Callback),
                                        ('/bet', MakeABet),
                                        ('/accept_bet', AcceptBet),
                                        ('/settle', SettleBet),
                                        ('/cancel', Cancel),
                                        ('/wtf', Wtf),
                                        ('/whatever', Whatever) ],
                                        debug=True)

def main():
    util.run_wsgi_app(application)

if __name__ == '__main__':
    main()
