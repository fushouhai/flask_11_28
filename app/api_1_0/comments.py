from . import api
from flask import jsonify
from ..models import Comment

@api.route('/comments/')
def get_comments():
    comments = Comment.query.all()
    return jsonify({'comments':[comment.to_json() for comment in comments]})

@api.route('/comments/<int:id>')
def get_comment(id):
    comment = Comment.query.get_or_404(id)
    return jsonify(comment.to_json())
