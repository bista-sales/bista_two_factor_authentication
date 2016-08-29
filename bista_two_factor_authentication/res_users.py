import openerp
from openerp import SUPERUSER_ID
from openerp import pooler, tools
from openerp import models, fields, api, _
import time
import struct
import hmac
import hashlib
import base64
import random
import urllib
import logging
_logger = logging.getLogger(__name__)
logger = logging.getLogger('product')


class ResUsers(models.Model):

    _inherit = 'res.users'

    @api.one
    def generate_secret_key(self):
        # generate 16 charecter base32 encoded string
        key = base64.b32encode(str(random.randint(1000000000, 9999999999)))
        key_exist = self.search([('secret_key', '=', key)])
        while len(key_exist):
            key = base64.b32encode(str(random.randint(1000000000, 9999999999)))
            key_exist = self.search([('secret_key', '=', key)])
        self.secret_key = key

    @api.one
    @api.constrains('secret_key')
    def _check_secret_key(self):
        if self.two_factor_authentication:
            if len(self.secret_key) < 16:
                raise Warning(_('Please Enter 16 digit key'))
            else:
                for each in self.secret_key:
                    if each.isdigit():
                        # range(2,8) means from 2 to 8
                        # excluding 8 and including 2
                        if not int(each) in range(2, 8):
                            raise Warning(_('Please Enter a digit '
                                            'in 2 to 8 range'))
                    else:
                        if not each.isupper():
                            raise Warning(_('Please Enter a character '
                                            'in uppercase letters'))

    @api.one
    def get_secret_key_url(self):
        username = self.login.replace(" ", "")
        secretkey = self.secret_key
        if not secretkey:
            raise Warning(_('Please Enter a character in uppercase letters'))
        domain = self.company_id.name.replace(" ", "")
        url = "https://www.google.com/chart"
        url += "?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/"
        url += username + "@" + domain + "?secret=" + secretkey
        return str(url)

    @api.one
    def send_secret_key(self):
        tmpl_obj = self.env['mail.template']
        # template_id = tmpl_obj.search(
        #     [('name', 'like', 'Send QR code')])
        template_id = self.env['ir.model.data'].get_object(
            'two_factor_authentication',
            'email_qr_code')
        if len(template_id):
            if not self.email:
                raise Warning(_('Please provide email id of the user.'))
            else:
                template_rec = tmpl_obj.browse(template_id.id)
                return template_rec.send_mail(self._uid, True)

    secret_key = fields.Char(string='Google Authenticator Secret Key', size=16,
                             help="Use combination of A-Z and "
                                  "2-7 only to create a secret key.")
    two_factor_authentication = fields.Boolean(
        string="Enable Two Factor Authentication via Google Authenticator.",
        default=False)
    mobile = fields.Char(
        string="Mobile number",
        size=64,
        help="This mobile number will receive the one time password"
        "(Eg: 61409317436 (Do not use + before the country code))")

    _sql_constraints = [
        ('secret_key_unique', 'UNIQUE (secret_key)',
         'Secret key already exists !')
    ]

    @api.onchange('two_factor_authentication')
    def onchange_clear_secret_key(self):
        if self.two_factor_authentication:
            self.generate_secret_key()
        else:
            self.secret_key = ''

    @tools.ormcache(skiparg=2)
    def check_credentials_google(self, cr, secretkey, token):
        """ Override this method to plug additional authentication methods"""

        tm = int(time.time() / 30)
        secretkey = base64.b32decode(secretkey)

        # try 30 seconds behind and ahead as well
        for ix in [-1, 0, 1]:
            # convert timestamp to raw bytes
            # print "---------ix----",ix
            b = struct.pack(">q", tm + ix)

        # generate HMAC-SHA1 from timestamp based on secret key
            hm = hmac.HMAC(secretkey, b, hashlib.sha1).digest()

        # extract 4 bytes from digest based on LSB
            offset = ord(hm[-1]) & 0x0F
            truncatedHash = hm[offset:offset + 4]

        # get the code from it
            code = struct.unpack(">L", truncatedHash)[0]
            code &= 0x7FFFFFFF
            code %= 1000000

            # _logger.info("%06d" % code)

            if ("%06d" % code) == str(token):
                return True
        raise openerp.exceptions.AccessDenied()

    def login_google(self, db, login, token):

        if not token:
            return False

        cr = pooler.get_db(db).cursor()
        try:
            # autocommit: our single update request
            # will be performed atomically.
            # (In this way, there is no opportunity to have two transactions
            # interleaving their cr.execute()..cr.commit() calls and have one
            # of them rolled back due to a concurrent access.)
            cr.autocommit(True)
            # check if user exists
            # res = self.search(cr, SUPERUSER_ID, [('login', '=', login)])
            #
            # if res:
            user_id = login
            user_record = self.browse(cr, SUPERUSER_ID, int(user_id))
            secret_key = user_record.secret_key
            # check credentials
            verified = self.check_credentials_google(cr, secret_key, token)
        except openerp.exceptions.AccessDenied:
            _logger.info("Login failed for db:%s login:%s", db, login)
            verified = False
        finally:
            cr.close()
        return verified

    def authenticate_google(self, db, login, token):
        verified = self.login_google(db, login, token)
        return verified

    def tfa_enabled(self, db, login):
        """Verifies and returns whether user has
         enabled Two Factor Authentication"""
        if not login:
            return False
        # user_id = False
        cr = pooler.get_db(db).cursor()
        try:
            # autocommit: our single update request
            # will be performed atomically.
            # (In this way, there is no opportunity to have two transactions
            # interleaving their cr.execute()..cr.commit() calls and have one
            # of them rolled back due to a concurrent access.)
            cr.autocommit(True)
            # check if user exists
            # res = self.search(cr, SUPERUSER_ID, [('login', '=', login)])
            # if res:
            #     user_id = res[0]
            user_id = login
            user_record = self.browse(cr, SUPERUSER_ID, user_id)
            # tfa_enabled_via_sms = user_record.two_factor_authentication_via_sms
            tfa_enabled = user_record.two_factor_authentication

        except openerp.exceptions.AccessDenied:
            _logger.info("Login failed for db:%s login:%s", db, login)
            tfa_enabled = False
        finally:
            cr.close()
        return tfa_enabled

    def send_sms(self, cr, otp_token, mobile_no):
        sms_config_obj = self.pool.get('sms.configuration')
        sms_search_rec = sms_config_obj.search(
            cr, SUPERUSER_ID, [
                ('active', '=', True)])
        sms_rec = sms_config_obj.browse(cr, SUPERUSER_ID, sms_search_rec)[0]
        message = str(sms_rec.message) + ' ' + str(otp_token)
        url = sms_rec.name + "username=" + sms_rec.username + "&password=" + \
            sms_rec.password + "&sendername=" + sms_rec.sender + \
            "&mobileno=" + mobile_no + "&message=" + message
        response = urllib.urlopen(str(url))
        response = response.read()
        _logger.info(response)
        return response

    def generate_otp(self, secretkey):
        """ This method generates One time password for """

        tm = int(time.time() / 30)

        secretkey = base64.b32decode(secretkey)

        b = struct.pack(">q", tm)

        # generate HMAC-SHA1 from timestamp based on secret key
        hm = hmac.HMAC(secretkey, b, hashlib.sha1).digest()

        # extract 4 bytes from digest based on LSB
        offset = ord(hm[-1]) & 0x0F
        truncatedHash = hm[offset:offset + 4]

        # get the code from it
        code = struct.unpack(">L", truncatedHash)[0]
        code &= 0x7FFFFFFF
        code %= 1000000

        return code
