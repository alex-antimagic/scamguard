from flask import Blueprint, redirect, render_template, url_for

portal_bp = Blueprint('portal', __name__, template_folder='../templates')


@portal_bp.route('/scan')
def scan():
    return render_template('portal/index.html')


@portal_bp.route('/docs')
def docs():
    # Legacy path — redirect to /api
    return redirect(url_for('marketing.api_docs'), code=301)
