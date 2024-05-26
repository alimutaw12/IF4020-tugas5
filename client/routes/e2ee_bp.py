from flask import Blueprint
from controllers.E2eeController import index, store, create

e2ee_bp = Blueprint('e2ee_bp', __name__)
e2ee_bp.route('/', methods=['GET'])(index)
e2ee_bp.route('/create', methods=['GET'])(create)
e2ee_bp.route('/store', methods=['POST'])(store)