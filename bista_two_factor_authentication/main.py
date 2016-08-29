from openerp import http
import openerp
from openerp.http import request
import werkzeug.utils
from openerp.addons.web.controllers.main import ensure_db,db_info
import json


class Home_Modified(openerp.addons.web.controllers.main.Home):

    @http.route('/web', type='http', auth="none")
    def web_client(self, s_action=None, **kw):
        ensure_db()
        if not request.session.uid:
            return werkzeug.utils.redirect('/web/login', 303)
        if request.session.uid:
            if kw.get('redirect'):
                return werkzeug.utils.redirect(kw.get('redirect'), 303)
            if not request.uid:
                request.uid = request.session.uid
            is_tfa = request.registry.get('res.users').browse(
                request.cr,
                request.uid,
                request.uid).two_factor_authentication

            if is_tfa:
                if 'twoAuth' in request.session and \
                        request.session.get('twoAuth', False):
                    menu_data = request.registry['ir.ui.menu'].load_menus(
                        request.cr,
                        request.uid,request.debug,
                        context=request.context)
                    return request.render('web.webclient_bootstrap', qcontext={'menu_data': menu_data, 'db_info': json.dumps(db_info())})
                else:
                    values = {'uid': request.session.uid}
                    return request.render(
                        'two_factor_authentication.web_security_code', values)
            else:
                menu_data = request.registry['ir.ui.menu'].load_menus(request.cr, request.uid, request.debug, context=request.context)
                return request.render('web.webclient_bootstrap', qcontext={'menu_data': menu_data, 'db_info': json.dumps(db_info())})

        # else:
        #     return login_redirect()


class Database(http.Controller):

    @http.route('/web/tfa_mode', type='http', auth="none")
    def tfa_mode(self, s_action=None, **kw):
        if request.session.uid:
            if not request.uid:
                request.uid = request.session.uid
            is_tfa = request.registry['res.users'].tfa_enabled(
                request.cr.dbname, request.uid)
            if is_tfa:
                values = {'uid': request.uid}
                return request.render(
                    'two_factor_authentication.web_security_code', values)
            else:
                return werkzeug.utils.redirect(kw.get('redirect'), 303)

    @http.route('/web/authenticate_google', type='http', auth="none", csrf=False)
    def authenticate_google(self, s_action=None, **kw):
        values = request.params.copy()
        gcode = values.get("gcode", False)
        uid = request.session.uid
        is_varified = False
        if gcode:
            is_varified = request.registry['res.users'].authenticate_google(
                request.cr.dbname, uid, gcode)
        if is_varified:
            request.session['twoAuth'] = True
            return werkzeug.utils.redirect('/web', 303)
        else:
            values = {
                'uid': request.uid,
                'failure': True,
                'failure_message': 'Invalid Code',
            }
            return request.render(
                'two_factor_authentication.web_security_code', values)
