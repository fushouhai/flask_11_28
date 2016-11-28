from . import api
from flask import jsonify
from ..exceptions import ValidationError

def bad_request(message):
    response = jsonify({'error':'Bad request', 'message':message})
    response.status_code = 400
    return response
 
@api.errorhandler(ValidationError)
def validation_error(e):
    return bad_request(e.args[0])

def forbidden(message):
    response = jsonify({'error': 'forbidden', 'message':message})
    response.status_code = 403
    return response

def unauthorized(message):
    response = jsonify({'error': 'Unauthorized', 'message':message})
    response.status_code = 401
    return response

def methodNotAllowed(message):
    response = jsonify({'error': 'Method not allowed', 'message':message})
    response.status_code = 405
    return response

