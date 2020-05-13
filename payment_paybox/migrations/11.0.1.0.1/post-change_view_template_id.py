import logging

from odoo import api, SUPERUSER_ID

_logger = logging.getLogger(__name__)


def migrate(cr, version):
    """Migrate v10 to v11.

    - Set paybox_form as view_template_id for all existing paybox acquirers
    """
    if not version:
        return

    with api.Environment.manage():
        env = api.Environment(cr, SUPERUSER_ID, {})

        paybox_form = env.ref('payment_paybox.paybox_form')
        paybox_acquirers = env['payment.acquirer'].with_context(active_test=False).search([
            ('provider', '=', 'paybox')
        ])
        paybox_acquirers.write({'view_template_id': paybox_form.id})
