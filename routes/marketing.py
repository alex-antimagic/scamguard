from flask import Blueprint, render_template

marketing_bp = Blueprint('marketing', __name__, template_folder='../templates')


@marketing_bp.route('/')
def landing():
    return render_template('marketing/landing.html')


@marketing_bp.route('/api')
def api_docs():
    return render_template('portal/docs.html')
