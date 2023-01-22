from flask import Flask,request,jsonify,make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from  werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
import re,http_request,threading,schedule

app  = Flask(__name__)
 
app.config['SECRET_KEY'] = 'b85ecd7351f1062bb3cee2896dff08f2'
 
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://rahim:$Aa123456@localhost/http_monitor' 
 
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True),
                           server_default=func.now())
    
    def __init__(self, username, password):
        self.username = username
        self.password = password

class Url(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    address = db.Column(db.String(100), nullable=False)
    threshold = db.Column(db.Integer, nullable=False)
    failed_times = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True),
                           server_default=func.now())
    
    def __init__(self,address,threshold,user_id) :
        self.address = address
        self.threshold = threshold
        self.user_id = user_id

class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    url_id = db.Column(db.Integer, db.ForeignKey('url.id'), nullable=False)
    code = db.Column(db.Integer)
    created_at = db.Column(db.DateTime(timezone=True),
                           server_default=func.now())
    
    def __init__(self,url_id,code) :
        self.url_id = url_id
        self.code = code

# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token,app.config['SECRET_KEY'],algorithms=['HS256'])
            current_user = User.query\
                .filter_by(id = data['id'])\
                .first()
        except Exception as err:
            print (err)
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return  f(current_user, *args, **kwargs)
  
    return decorated

@app.route('/login', methods =['POST'])
def login():
    auth = request.form
  
    if not auth or not auth.get('username') or not auth.get('password'):
        # returns 401 if any username or password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
        )
  
    user = User.query\
        .filter_by(username = auth.get('username'))\
        .first()
  
    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
        )
  
    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'id': user.id,
            'exp' : datetime.utcnow() + timedelta(minutes = 60)
        }, app.config['SECRET_KEY'])
  
        return make_response(jsonify({'token' : token}), 201)
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
    )

@app.route('/register', methods=['POST'])
def register(): 
    data = request.form
  
    # gets username and password
    username = data.get('username')
    password = data.get('password')
  
    # checking for existing user
    user = User.query\
        .filter_by(username = username)\
        .first()
    if not user:
        # database ORM object
        user = User(
            username=username,
            password = generate_password_hash(password,method="md5")
        )
        # insert user
        db.session.add(user)
        db.session.commit()

        # generates the JWT Token
        token = jwt.encode({
            'id': user.id,
            'exp' : datetime.utcnow() + timedelta(minutes = 60)
        }, app.config['SECRET_KEY'])
  
        return make_response(jsonify({
            'token' : token,
            'message':"Successfully registered."}), 201)
  
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)


@app.route('/urls', methods =['POST','GET'])
@token_required
def urls(current_user):
    if request.method == 'POST':
        data = request.form

        # get address and threshold
        address = data.get('address')
        threshold = data.get('threshold')

        if(address == None or threshold == None):
            return jsonify({'message' : 'Address and threshold are required.'}),400
        if(not re.compile("https?://[\w]*[.][\w]*").match(address)):
            return jsonify({'message' : 'Url is not in correct format.'}),400
        
        url = Url(address,threshold,current_user.id)
        # insert url
        db.session.add(url)
        db.session.commit()
        return jsonify({'message' : 'url has been added successfully.'}),201
    else :
        urls = Url.query.filter_by(user_id=current_user.id).all()
        output = []
        for url in urls:
            url_data = {}
            url_data['id'] = url.id
            url_data['address'] = url.address
            url_data['threshold'] = url.threshold
            
            output.append(url_data)
        
    
        return jsonify({'users': output})

@app.route('/urls/<url_id>', methods =['GET'])
@token_required
def url_requests(current_user,url_id):
    from_date = datetime(year=datetime.now().year, month=datetime.now().month, day=1)

    requests = Request.query.filter_by(url_id=url_id).filter(Request.created_at >= from_date).all()
    output = []
    for request in requests:
        req_data = {}
        url = Url.query.filter_by(id=request.url_id).first()
        req_data['url'] = url.address
        req_data['code'] = request.code
        req_data['request_time'] = request.created_at
        
        output.append(req_data)
    

    return jsonify({'users': output})

@app.route('/alerts', methods =['GET'])
@token_required
def alerts(current_user):
    urls = Url.query.filter(Url.failed_times>=Url.threshold).all()
    output = []
    for url in urls:
        output.append(url.address)
    response = {'failed_urls':output}
    if (len(output)!=0):
        response['alert_message'] = 'Url(s) has reached maximum failure.'
    print(response)
    return jsonify(response),201



def run_threaded(job_func):
    job_thread = threading.Thread(target=job_func)
    job_thread.start()

def run_app():
    app.run()

if __name__ == "__main__":
    threading.Thread(target = run_app).start()
    
    schedule.every(900).seconds.do(run_threaded, http_request.periodic_request)    
    while 1:
        schedule.run_pending()
    
    