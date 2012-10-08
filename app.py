from flask import Flask, redirect, url_for, session, request, render_template
from flask_oauth import OAuth
import urlparse
import logging
import hmac
import hashlib
import base64
import json
import os
from urllib import urlencode
from config import *

app = Flask(__name__)
app.secret_key = 'abcdeghji'
app.debug = True
oauth = OAuth()

facebook = oauth.remote_app('facebook',
    base_url=BASE_URL,
    request_token_url=REQUEST_TOKEN_URL,
    access_token_url=ACCESS_TOKEN_URL,
    authorize_url=AUTHORIZE_URL,
    consumer_key=CONSUMER_KEY,
    consumer_secret=CONSUMER_SECRET,
    request_token_params={'scope': 'user_photos, user_photo_video_tags,  friends_photo_video_tags',},
)

def validate_signed_fb_request(signed_request):
    """ Returns dictionary with signed request data """
    try:
        l = signed_request.split('.', 2)
        encoded_sig = str(l[0])
        payload = str(l[1])
    except IndexError:
        raise ValueError("'signed_request' malformed")
    
    sig = base64.urlsafe_b64decode(encoded_sig + "=" * ((4 - len(encoded_sig) % 4) % 4))
    data = base64.urlsafe_b64decode(payload + "=" * ((4 - len(payload) % 4) % 4))
    
    data = json.loads(data)
    
    if data.get('algorithm').upper() != 'HMAC-SHA256':
        raise ValueError("'signed_request' is using an unknown algorithm")
    else:
        expected_sig = hmac.new(CONSUMER_SECRET, msg=payload, digestmod=hashlib.sha256).digest()
    
    if sig != expected_sig:
        raise ValueError("'signed_request' signature mismatch")
    else:
        return data


@app.route('/', methods=['GET', 'POST'])
def index():
    #print request.form['signed_request']
    '''
	signed_data = validate_signed_fb_request(request.form['signed_request'])
    if signed_data.has_key('oauth_token'):
        #print signed_data['oauth_token']
        session['oauth_token'] = (signed_data['oauth_token'], '')
        session['user'] = signed_data['user_id']
        logging.debug('Logged user: %s', signed_data)
        return redirect(url_for('home'))

    return redirect(url_for('login'))
	'''
    token = request.args.get('access_token')
    if token and token != 'null':
        session['oauth_token'] = (token, '')
        return redirect(url_for('home'))
    else:
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    return facebook.authorize(callback=url_for('facebook_authorized',
        next=request.args.get('next') or request.referrer or None,
        _external=True))

@app.route('/login/authorized', methods=['GET', 'POST'])
@facebook.authorized_handler
def facebook_authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    
    session['oauth_token'] = (resp['access_token'], '')
    #print session['oauth_token']
    
    return redirect(url_for('home'))

@app.route('/home', methods=['GET', 'POST'])
def home():
    me = facebook.get('/me')
    return render_template('index.html')

@app.route('/photos', methods=['GET', 'POST'])
def photos():
    url = '/me/photos?fields=source'
    try:
        if request.form['limit'] and request.form['until']:
            url += '&limit=%s&until=%s' % (request.form['limit'], request.form['until'])
    except KeyError:
        pass
    
    photos = facebook.get(url)
    return_dict = {'photos': []}
    for photo in photos.data['data']:
        return_dict['photos'].append(photo['source'])
    params = urlparse.parse_qs(photos.data['paging']['next'])
    return_dict['limit'] = params['limit'][0]
    return_dict['until'] = params['until'][0]
    
    return json.dumps(return_dict)

def batch_requests(*args):
    request = []
    for (method, relative_url, body) in args:
        per_request = {}
        if method is None:
            method = 'GET'
        per_request['method'] = method
        per_request['relative_url'] = relative_url
        if body is not None:
            per_request['body'] = body
        request.append(per_request)
    
    response = facebook.post('/', data={
                                    'access_token': get_facebook_oauth_token(),
                                    'batch': json.dumps(request),},\
                )
    import pprint
    pprint.pprint(request)
    pprint.pprint(response.data)

def _get_details(user='me'):
    me = facebook.get('/%s' % user)
    return me.data


@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('oauth_token')


if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
