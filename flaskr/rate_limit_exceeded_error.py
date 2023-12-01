from flask import  make_response

#Custom rate limit error
def ratelimit_handler(e):
    """Custom error"""
    return make_response("Ratelimit exceeded.")