import openerp
import werkzeug.contrib.sessions
import werkzeug.utils
request = openerp.http.request


def redirect_with_hash(url, code=303):
    if request.uid:
        res_users_enable = request.registry.get('res.users').browse(
            request.cr,
            request.uid,
            request.uid).two_factor_authentication
        if res_users_enable:
            url = "/web/tfa_mode"
            if request.httprequest.user_agent.browser in ('firefox',):
                return werkzeug.utils.redirect(url, code)
            return "<html><head><script>window.location = '%s' + " \
                   "location.hash;" \
                   "</script></head></html>" % url
        else:
            if request.httprequest.user_agent.browser in ('firefox',):
                return werkzeug.utils.redirect(url, code)
        return "<html><head><script>window.location = '%s' + location.hash;" \
               "</script></head></html>" % url
    else:
        if request.httprequest.user_agent.browser in ('firefox',):
            return werkzeug.utils.redirect(url, code)
        return "<html><head><script>window.location = '%s' + location.hash;" \
               "</script></head></html>" % url


openerp.http.redirect_with_hash = redirect_with_hash
