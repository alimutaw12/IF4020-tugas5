from flask import Blueprint
from controllers.DsController import index, create, store

ds_bp = Blueprint('ds_bp', __name__)
ds_bp.route('/', methods=['GET'])(index)
ds_bp.route('/create', methods=['GET'])(create)
ds_bp.route('/store', methods=['POST'])(store)