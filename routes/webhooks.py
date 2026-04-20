import logging

from flask import Blueprint, request, jsonify

from services.billing_service import handle_webhook

webhooks_bp = Blueprint('webhooks', __name__, url_prefix='/webhooks')

logger = logging.getLogger(__name__)


@webhooks_bp.route('/stripe', methods=['POST'])
def stripe_webhook():
    payload = request.get_data()
    sig = request.headers.get('Stripe-Signature', '')

    event_type, ok = handle_webhook(payload, sig)
    if not ok:
        return jsonify({'error': 'Invalid signature'}), 400

    return jsonify({'received': True, 'event': event_type}), 200
