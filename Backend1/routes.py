from app import app

@app.route('/')
def home():
    return "Secure Token Based Malpractice Prevention , Hello World!"


@app.route('/gettoken')
def getToken():
    pass