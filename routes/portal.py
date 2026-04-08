from flask import Blueprint, render_template

portal_bp = Blueprint('portal', __name__, template_folder='../templates')


@portal_bp.route('/')
def index():
    return render_template('portal/index.html')
