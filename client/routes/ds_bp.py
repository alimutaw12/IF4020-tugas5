from flask import Blueprint
from controllers.DsController import index

ds_bp = Blueprint('ds_bp', __name__)
ds_bp.route('/', methods=['GET'])(index)