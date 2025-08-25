import hashlib
import urllib.parse
import hmac
import binascii
import requests
from datetime import datetime, timezone

from odoo import api, fields, models, _
from odoo.exceptions import UserError
from odoo.tools import float_round


class PayboxAcquirer(models.Model):
    _inherit = 'payment.acquirer'

    provider = fields.Selection(selection_add=[('paybox', "Paybox")])

    paybox_site = fields.Char("Paybox Site Number")
    paybox_rank = fields.Char("Paybox Rank Number")
    paybox_id = fields.Char("Paybox Internal ID")

    # Authentication key generate in the Paybox Back Office
    paybox_authentication_key = fields.Char(string="Paybox Authentication Key", required_if_provider='paybox')

    # Authentication key generation in the Paybox Back Office Preprod
    paybox_test_authentication_key = fields.Char(
        string="Paybox Test Authentication Key",
    )

    # Paybox SSH Public Key
    paybox_public_key = fields.Binary(string="Paybox Public Key")

    @api.model
    def paybox_generate_message_hmac(self, vals):
        return '&'.join(['%s=%s' % (key, value) for key, value in vals.items()]).encode('utf-8')

    def paybox_get_form_action_url(self):
        """Get the form action url that depends to the chosen environment

        :return: The form action url string
        """
        self.ensure_one()
        prod_url = 'https://tpeweb.paybox.com/cgi/MYchoix_pagepaiement.cgi'
        backup_url = 'https://tpeweb1.paybox.com/cgi/MYchoix_pagepaiement.cgi'
        preprod_url = 'https://preprod-tpeweb.paybox.com/cgi/MYchoix_pagepaiement.cgi'

        if self.state == 'enabled':
            response = requests.get(prod_url)
            if response.ok:
                return prod_url
            response = requests.get(backup_url)
            if response.ok:
                return backup_url
            raise Exception(_('Paybox server is unavailable!'))
        elif self.state == 'test':
            response = requests.get(preprod_url)
            if response.ok:
                return preprod_url
            raise Exception(_('Paybox server is unavailable!'))

        raise UserError(_("Couldn't pay with disabled payment acquirer."))

    def paybox_get_authentication_key(self):
        """Get the authentication key that depends to the chosen environment

        :return: The authentication key string
        """
        self.ensure_one()

        if self.state == 'enabled':
            return self.paybox_authentication_key
        elif self.state == 'test':
            return self.paybox_test_authentication_key
        raise UserError(_("Couldn't pay with disabled payment acquirer."))

    def paybox_form_generate_values(self, values):
        """Generate the values to send to Paybox

        :param values: Dictionary which contains all information of the transaction
        :return: Dict
        """
        self.ensure_one()

        paybox_tx_values = dict((k, v) for k, v in list(values.items()) if v)

        base_url = self.env['ir.config_parameter'].get_param('web.base.url')
        prec = self.env['decimal.precision'].precision_get('Product Price')

        auth_key = self.paybox_get_authentication_key()

        dpn_url = urllib.parse.urljoin(base_url, '/payment/paybox/dpn?return_url=%s' % values.get('return_url'))
        ipn_url = urllib.parse.urljoin(base_url, '/payment/paybox/ipn')

        # We create a list of tuples because to create the message, the datas must be sort in the same order than
        # the form we send to Paybox
        vals = {
            'PBX_SITE': self.paybox_site,
            'PBX_RANG': self.paybox_rank,
            'PBX_IDENTIFIANT': self.paybox_id,
            'PBX_TOTAL': int(float_round(values['amount'] * 100, prec)),
            'PBX_DEVISE': values.get('currency').number,
            'PBX_CMD': values.get('reference').replace('/', ' '),
            'PBX_PORTEUR': values.get('partner_email'),
            'PBX_RETOUR': 'amount:M;reference:R;response:E;transaction:S;signature:K',
            'PBX_HASH': 'SHA512',
            'PBX_TIME': datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            'PBX_EFFECTUE': dpn_url,
            'PBX_REFUSE': dpn_url,
            'PBX_ANNULE': dpn_url,
            'PBX_ATTENTE': dpn_url,
            'PBX_REPONDRE_A': ipn_url,
        }

        signature = self.paybox_generate_message_hmac(vals)
        key_bin = binascii.unhexlify(auth_key)
        signature_hmac = hmac.new(key_bin, signature, hashlib.sha512).hexdigest()

        vals['PBX_HMAC'] = signature_hmac.upper()

        paybox_tx_values.update(dict(vals))

        return paybox_tx_values
