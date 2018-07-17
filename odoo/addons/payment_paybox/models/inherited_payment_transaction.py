# -*- coding: utf-8 -*-

import logging

from odoo import _, api, fields, models
from odoo.exceptions import ValidationError
from odoo.tools.float_utils import float_compare
import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

_logger = logging.getLogger(__name__)

PAYBOX_CODE_RESPONSE = {
    '00000': _('Approved'),
    '00001': _('Canceled or connection to the authorization center failed or an internal error occured'),
    '00003': _('Paybox Error'),
    '00004': _('Card number invalid or visual cryptogram invalid'),
    '00006': _('Access refused or site/rank/identifier incorrect'),
    '00008': _('Incorrect expiry date'),
    '00009': _('Error when during subscriber creation'),
    '00010': _('Unknown currency'),
    '00011': _('Amount incorrect'),
    '00015': _('Payment already done'),
    '00016': _('Subscriber already exists'),
    '00021': _('Not authorized bin card'),
    '00029': _('Not the same card used for the first payment'),
    '00030': _('Timeout'),
    '00031': _('Reserved'),
    '00032': _('Reserved'),
    '00033': _('Unauthorized country code of the IP address of the cardholder\'s browser'),
    '00040': _('Operation without 3DSecure authentication, blocked by the fraud filter'),
    '99999': _('Payment waiting confirmation from the issuer')
}


class PayboxTransaction(models.Model):

    _inherit = 'payment.transaction'

    @api.model
    def _paybox_form_get_tx_from_data(self, data):
        """ Method called by form_feedback after the transaction

        :param data: data received from the acquirer after the transaction
        :return: payment.transaction record if retrieved or an exception
        """

        reference = data.get('reference').replace(' ', '/')
        transaction = self.sudo().search([('reference', '=', reference)])

        if not transaction or len(transaction) > 1:
            error_msg = 'SystemPay: received bad data for reference {}'.format(reference)

            if not transaction:
                error_msg += '; no order found'
            else:
                error_msg += '; multiple order found'

            _logger.info(error_msg)
            raise ValidationError(error_msg)

        # Verify the signature give in the data
        # List of tuples to create the message to create signature
        vals = []
        if data.get('return_url', False):
            vals.append(('return_url', str(data.get('return_url'))))

        if data.get('amount', False):
            vals.append(('amount', str(data.get('amount'))))

        extend_vals = [
            ('reference', str(data.get('reference'))),
            ('response', str(data.get('response'))),
            ('transaction', str(data.get('transaction')))
        ]

        vals.extend(extend_vals)

        # Get the paybox public key store in the odoo database
        key = RSA.importKey(base64.b64decode(transaction.acquirer_id.paybox_public_key))

        # Code get from : https://github.com/pmhoudry/pythonPaybox
        signature = data.get('signature')
        message = self.env['payment.acquirer'].paybox_generate_message_hmac(vals)
        h = SHA.new(message)
        verifier = PKCS1_v1_5.new(key)
        binary_signature = base64.b64decode(signature)

        assert verifier.verify(h, binary_signature), _('Signature Verification Failed')

        return transaction

    @api.multi
    def _paybox_form_get_invalid_parameters(self, data):
        """ Check the differents parameters with the transaction store in odoo

        :param data: data received from paybox at the end of transaction
        :return: List of differents invalid parameters if there is
        """
        self.ensure_one()

        invalid_parameters = []

        if self.acquirer_reference and data.get('transaction') != self.acquirer_reference:
            invalid_parameters.append(
                ('transaction_reference', data.get('transaction'), self.acquirer_reference)
            )

        # If transaction is canceled, Paybox does not return the amount
        if data.get('response') == '00000':
            if float_compare(float(data.get('amount', '0.0')) / 100, self.amount, 2) != 0:
                invalid_parameters.append(
                    ('amount', data.get('amount'), '%.2f' % self.amount)
                )

        return invalid_parameters

    @api.multi
    def _paybox_form_validate(self, data):
        """ Check the status of the transaction and set it accordingly

        :param data: data received from paybox at the end of transaction
        """

        self.ensure_one()
        values = {
            'acquirer_reference': data.get('transaction')
        }

        transaction_status = data.get('response')

        if transaction_status[:3] == '001':
            _logger.info('Payment rejected by the authorization center')
            _logger.info('Validated Paybox payment for transaction %s: set as error' % self.reference)
            values['state'] = 'error'
            values['state_message'] = 'Payment rejected by the authorization center'

        if transaction_status in PAYBOX_CODE_RESPONSE.iterkeys():
            _logger.info(PAYBOX_CODE_RESPONSE[transaction_status])

            # Status code when the transaction is done
            if transaction_status == '00000':
                state = 'done'
                values['date_validate'] = fields.Datetime.now()

            # Status code when the transaction is pending
            elif transaction_status == '99999':
                state = 'pending'

            # Status code when the transaction is canceled
            elif transaction_status == '00001':
                state = 'cancel'

            else:
                state = 'error'

            _logger.info('Validated Paybox payment for transaction %s: set as %s' % (self.reference, state))
            values['state'] = state
            values['state_message'] = PAYBOX_CODE_RESPONSE[transaction_status]

        return self.write(values)
