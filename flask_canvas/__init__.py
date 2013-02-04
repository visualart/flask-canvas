import hmac
import facebook
from hashlib import sha256
from functools import wraps
from base64 import urlsafe_b64decode
from werkzeug.local import LocalProxy

from flask import Blueprint, request, json, current_app, flash, session, \
        redirect

_default_msg = {
    'CANVAS_MSG_UNAUTHORIZED':
        'You are not allowed to access this page as you are not an '
        'administrator of this page.'
}

_logger = LocalProxy(lambda: current_app.logger)


class Canvas(object):
    def __init__(self, app=None):
        self.app = app

        if self.app is not None:
            self.init_app(app)

    def init_app(self, app):
        for key, val in _default_msg.items():
            app.config.setdefault(key, val)

        blueprint = Blueprint('canvas', __name__)

        @blueprint.before_app_request
        def update_session():
            signed_data = self.get_signed_request_data()

            if signed_data and not signed_data == session.get('signed_data'):
                session['signed_data'] = signed_data

                if signed_data.get('user_id'):
                    session['user_data'] = self.get_user_data(signed_data['user_id'])
                    session['is_page_admin'] = self.is_page_admin()

        @blueprint.app_context_processor
        def inject_user():
            return {
                'user': session.get('user_data'),
                'user_is_page_admin': self.is_page_admin()}

        app.register_blueprint(blueprint)

    def get_user_data(self, user_id):
        if not session.get('signed_data') \
           or not session['signed_data'].get('oauth_token'):
            raise KeyError('oauth_token not present')

        graph = facebook.GraphAPI(session['signed_data']['oauth_token'])

        return graph.get_object(user_id)

    @property
    def user(self):
        return session.get('user_data')

    def page_admin_required(self, page_id=None):
        def decorator(view_func):
            @wraps(view_func)
            def wrapper(*args, **kw):
                if not self.is_page_admin(page_id):
                    flash(
                        unicode(
                            current_app.config['CANVAS_MSG_UNAUTHORIZED']),
                        u'error')
                    return redirect(
                        current_app.config.get('CANVAS_UNAUTHORIZED_REDIRECT', '/'))

                return view_func(*args, **kw)
            return wrapper
        return decorator

    def is_page_admin(self, page_id=None):
        page_id = page_id or current_app.config['CANVAS_PAGE_ID']

        if not page_id:
            raise ValueError(
                'CANVAS_PAGE_ID must be set, or you must pass the page '
                'id to page_admin_required')

        signed_data = session.get('signed_data')

        if not signed_data or not signed_data.get('page'):
            return False

        return signed_data['page']['admin'] \
                and int(signed_data['page']['id']) == page_id

    def get_signed_request_data(self, signed_request=None):
        signed_request = signed_request or request.form.get('signed_request')

        if signed_request:
            encoded_sig, payload = signed_request.split('.')
            data = json.loads(
                urlsafe_b64decode(
                    str(payload) + (64 - len(payload) % 64) * '='
                    ))

            if not data['algorithm'] == u'HMAC-SHA256':
                raise TypeError(
                    'Unknown encryption "{0}". Expected "HMAC-SHA256"'.format(
                        data['algorithm']))

            if not 'CANVAS_SECRET' in current_app.config.keys():
                raise ValueError(
                    'CANVAS_SECRET must be set to the Facebook app secret.')

            expected_sig = hmac.new(
                current_app.config['CANVAS_SECRET'],
                str(payload),
                sha256).digest()
            sig = urlsafe_b64decode(
                str(encoded_sig) + ('=' * (4 - (len(encoded_sig) % 4))))

            if not sig == expected_sig:
                raise AssertionError(
                    'Unexpected signature "{0}", expected "{1}"'.format(
                        sig,
                        expected_sig))

            return data
        return None
