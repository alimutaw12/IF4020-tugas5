from flask import Blueprint
from controllers.DsController import index, create, store, read, verify

ds_bp = Blueprint('ds_bp', __name__)
ds_bp.route('/', methods=['GET'])(index)
ds_bp.route('/create', methods=['GET'])(create)
ds_bp.route('/store', methods=['POST'])(store)
ds_bp.route('/read/<int:document_id>', methods=['GET'])(read)
ds_bp.route('/verify/<int:document_id>', methods=['POST'])(verify)
