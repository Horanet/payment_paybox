# -*- coding: utf-8 -*-

from odoo import api, fields, models, _
from datetime import datetime
import hashlib
import urlparse
import logging
import hmac
import binascii

_logger = logging.getLogger(__name__)


class PayboxAcquirer(models.Model):
    _inherit = 'payment.acquirer'

    provider = fields.Selection(selection_add=[('paybox', 'Paybox')])

    paybox_site = fields.Char('Paybox Site Number')
    paybox_rank = fields.Char('Paybox Rank Number')
    paybox_id = fields.Char('Paybox Internal ID')

    paybox_form_action_url = fields.Char(
        string='Form action URL',
        default='https://tpeweb.paybox.com/cgi/MYchoix_pagepaiement.cgi/',
        required_if_provider='paybox'
    )

    paybox_form_action_url_test = fields.Char(
        string='Form action URL Test',
        default='https://preprod-tpeweb.paybox.com/cgi/MYchoix_pagepaiement.cgi/',
        required_if_provider='paybox'
    )

    # Authentication key generate in the Paybox Back Office
    paybox_authentication_key = fields.Char(
        string='Paybox Authentication Key',
        required_if_provider='paybox'
    )

    # Authentication key generation in the Paybox Back Office Preprod
    paybox_test_authentication_key = fields.Char(
        string='Paybox Test Authentication Key'
    )

    # Paybox SSH Public Key
    paybox_public_key = fields.Binary(string='Paybox Public Key')

    @api.model
    def paybox_generate_message_hmac(self, values):
        """ Generate the message to create the HMAC

        :param values: List of tuples which contains all parameters we will send to Paybox
        :return: Message string
        """
        signature = ''
        for k, v in values:
            s = '%s=%s' % (k, v)
            if signature:
                s = '&' + s

            signature += s

        return signature

    @api.multi
    def paybox_get_form_action_url(self):
        """ Get the form action url that depends to the chosen environment

        :return: The form action url string
        """
        self.ensure_one()

        if self.environment == "prod":
            return self.paybox_form_action_url
        else:
            return self.paybox_form_action_url_test

    @api.multi
    def paybox_get_authentication_key(self):
        """ Get the authentication key that depends to the chosen environment

        :return: The authentication key string
        """
        self.ensure_one()

        if self.environment == "prod":
            return self.paybox_authentication_key
        else:
            return self.paybox_test_authentication_key


    @api.multi
    def paybox_form_generate_values(self, values):
        """ Generate the values to send to Paybox

        :param values: Dictionary which contains all information of the transaction
        :return: Dict
        """
        self.ensure_one()

        paybox_tx_values = dict((k, v) for k, v in values.items() if v)

        base_url = self.env['ir.config_parameter'].get_param('web.base.url')

        key = self.paybox_get_authentication_key()

        # We create a list of tuples because to create the message, the datas must be sort in the same order than
        # the form we send to Paybox
        vals = [
            ('PBX_SITE', self.paybox_site),
            ('PBX_RANG', self.paybox_rank),
            ('PBX_IDENTIFIANT', self.paybox_id),
            ('PBX_TOTAL', int(values['amount'] * 100)),
            ('PBX_DEVISE', values.get('currency').number),
            ('PBX_CMD', values.get('reference').replace('/', ' ')),
            ('PBX_PORTEUR', values.get('partner_email')),
            ('PBX_RETOUR', 'amount:M;reference:R;response:E;transaction:S;signature:K'),
            ('PBX_HASH', 'SHA512'),
            ('PBX_TIME', datetime.utcnow().replace(microsecond=0).isoformat()),
            ('PBX_EFFECTUE', urlparse.urljoin(base_url, '/payment/paybox/dpn?return_url=%s' % values.get('return_url'))),
            ('PBX_REFUSE', urlparse.urljoin(base_url, '/payment/paybox/dpn?return_url=%s' % values.get('return_url'))),
            ('PBX_ANNULE', urlparse.urljoin(base_url, '/payment/paybox/dpn?return_url=%s' % values.get('return_url'))),
            ('PBX_ATTENTE', urlparse.urljoin(base_url, '/payment/paybox/dpn?return_url=%s' % values.get('return_url'))),
            ('PBX_REPONDRE_A', urlparse.urljoin(base_url, '/payment/paybox/ipn'))
        ]

        signature = self.paybox_generate_message_hmac(vals)

        key_bin = binascii.unhexlify(key)
        signature_hmac = hmac.new(key_bin, signature, hashlib.sha512).hexdigest()

        vals.append(('PBX_HMAC', signature_hmac.upper()))

        paybox_tx_values.update(dict(vals))

        return paybox_tx_values
