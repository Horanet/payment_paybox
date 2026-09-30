import base64
import logging

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

from odoo import _, api, fields, models
from odoo.exceptions import ValidationError
from odoo.tools.float_utils import float_compare

_logger = logging.getLogger(__name__)

PAYBOX_CODE_RESPONSE = {
    '00000': _("Approved"),
    '00001': _("Canceled or connection to the authorization center failed or an internal error occured"),
    '00003': _("Paybox Error"),
    '00004': _("Card number invalid or visual cryptogram invalid"),
    '00006': _("Access refused or site/rank/identifier incorrect"),
    '00008': _("Incorrect expiry date"),
    '00009': _("Error when during subscriber creation"),
    '00010': _("Unknown currency"),
    '00011': _("Amount incorrect"),
    '00015': _("Payment already done"),
    '00016': _("Subscriber already exists"),
    '00021': _("Not authorized bin card"),
    '00029': _("Not the same card used for the first payment"),
    '00030': _("Timeout"),
    '00031': _("Reserved"),
    '00032': _("Reserved"),
    '00033': _("Unauthorized country code of the IP address of the cardholder's browser"),
    '00040': _("Operation without 3DSecure authentication, blocked by the fraud filter"),
    '99999': _("Payment waiting confirmation from the issuer"),
}

AUTORIZATION_CENTER_RESPONSE_CODE = {
    '00': _("Approved"),
    '01': _("Contact card issuer"),
    '02': _("Contact card issuer"),
    '03': _("Invalid merchant"),
    '04': _("Keep card"),
    '05': _("Do not honor"),
    '07': _("Keep card, special conditions"),
    '08': _("Approve after cardholder identification"),
    '12': _("Invalid transaction"),
    '13': _("Invalid amount"),
    '14': _("Invalid cardholder number"),
    '15': _("Unknown card issuer"),
    '17': _("Customer cancellation"),
    '19': _("Repeat transaction later"),
    '20': _("Incorrect response"),
    '24': _("File update not supported"),
    '25': _("File update not supported"),
    '26': _("Duplicate record, old record replaced"),
    '27': _("Error in \"edit\" field File update"),
    '28': _("File access denied"),
    '29': _("File update impossible"),
    '30': _("Format error"),
    '31': _("Acquiring organization ID unknown"),
    '33': _("Card expiration date expired"),
    '34': _("Suspected fraud"),
    '38': _("Number of PIN attempts exceeded"),
    '41': _("Lost card"),
    '43': _("Stolen card"),
    '51': _("Insufficient funds or credit exceeded"),
    '54': _("Card validity date exceeded"),
    '55': _("Incorrect PIN"),
    '56': _("Card not in file"),
    '57': _("Transaction not permitted for this cardholder"),
    '58': _("Transaction prohibited at the terminal"),
    '59': _("Suspected fraud"),
    '60': _("The card acceptor must contact the acquirer"),
    '61': _("Exceeds the withdrawal amount limit"),
    '63': _("Security rules not respected"),
    '68': _("Response not received or received too late"),
    '75': _("Number of PIN attempts exceeded"),
    '76': _("Cardholder already blocked, old record retained"),
    '89': _("Authentication failure"),
    '90': _("Temporary system shutdown"),
    '91': _("Card issuer inaccessible"),
    '94': _("Duplicate request"),
    '96': _("System malfunction"),
    '97': _("Global monitoring timeout expired"),
    '98': _("Server unreachable"),
    '99': _("Initiating domain incident"),
}


class PayboxTransaction(models.Model):
    _inherit = 'payment.transaction'

    @api.model
    def _paybox_form_get_tx_from_data(self, data):
        """Method called by form_feedback after the transaction

        :param data: data received from the acquirer after the transaction
        :return: payment.transaction record if retrieved or an exception
        """
        reference = data.get('reference')
        if not reference:
            error_msg = _('Paybox: received data with missing reference (%s) ') % (reference)
            _logger.info(error_msg)
            raise ValidationError(error_msg)
        reference = reference.replace(' ', '/')
        transaction = self.sudo().search([('reference', '=', reference)])

        if not transaction or len(transaction) > 1:
            error_msg = "Paybox: received bad data for reference {}".format(reference)

            if not transaction:
                error_msg += "; no order found"
            else:
                error_msg += "; multiple order found"

            _logger.info(error_msg)
            raise ValidationError(error_msg)
        elif transaction.acquirer_reference and data.get('transaction') != transaction.acquirer_reference:
            # In Paybox, if an error occurs due to 3DSecure authentication for example, Paybox store the transaction as
            # an error and call IPN route. It means that the transaction in Odoo is updated, the state is set as
            # 'error', and store the acquirer reference in it. But Paybox does not redirect to Odoo after this error,
            # the user is allowed to retry the payment, if so, it generates a new reference in Paybox. So when the user
            # pay, the IPN route is called with another reference, and we get an error where it's impossible to update
            # the transaction because the references are different.
            # We first search for an existing transaction which generate a new transaction with a reference updated,
            # to have the same history as Paybox.
            reference_transaction = transaction.reference.split('x')
            if reference_transaction:
                existing_transaction = transaction.search(
                    [
                        ('reference', 'like', reference_transaction[0]),
                        ('acquirer_reference', '=', data.get('transaction')),
                    ]
                )
                if existing_transaction:
                    transaction = existing_transaction
                else:
                    transaction = transaction.copy(
                        {
                            'acquirer_reference': False,
                        }
                    )

        # Verify the signature give in the data
        # List of tuples to create the message to create signature
        vals = {}
        if data.get('return_url', False):
            vals['return_url'] = str(data.get('return_url'))

        if data.get('amount', False):
            vals['amount'] = str(data.get('amount'))

        vals.update(
            {
                'reference': str(data.get('reference')),
                'response': str(data.get('response')),
                'transaction': str(data.get('transaction')),
            }
        )
        # Get the paybox public key store in the odoo database
        key = RSA.importKey(base64.b64decode(transaction.acquirer_id.paybox_public_key))

        # Code get from : https://github.com/pmhoudry/pythonPaybox
        signature = data.get('signature')
        message = self.env['payment.acquirer'].paybox_generate_message_hmac(vals)
        h = SHA.new(message)
        verifier = PKCS1_v1_5.new(key)
        binary_signature = base64.b64decode(signature)

        assert verifier.verify(h, binary_signature), _("Signature Verification Failed")

        return transaction

    def _paybox_form_get_invalid_parameters(self, data):
        """Check the differents parameters with the transaction store in odoo

        :param data: data received from paybox at the end of transaction
        :return: List of differents invalid parameters if there is
        """
        self.ensure_one()

        invalid_parameters = []

        if self.acquirer_reference and data.get('transaction') != self.acquirer_reference:
            invalid_parameters.append(('transaction_reference', data.get('transaction'), self.acquirer_reference))

        # If transaction is canceled, Paybox does not return the amount
        if data.get('response') == '00000':
            if float_compare(float(data.get('amount', '0.0')) / 100, self.amount, 2) != 0:
                invalid_parameters.append(('amount', data.get('amount'), '%.2f' % self.amount))

        return invalid_parameters

    def _paybox_form_validate(self, data):
        """Check the status of the transaction and set it accordingly

        :param data: data received from paybox at the end of transaction
        """

        self.ensure_one()
        values = {'acquirer_reference': data.get('transaction')}

        transaction_status = data.get('response')

        if transaction_status[:3] == '001':
            autorization_center_code = transaction_status[3:]
            _logger.info("Payment rejected by the authorization center")
            _logger.info("Validated Paybox payment for transaction %s: set as error" % self.reference)
            values.update(
                {
                    'state': 'error',
                    'state_message': _("Payment rejected by the authorization center (%s - %s)")
                    % (
                        autorization_center_code,
                        AUTORIZATION_CENTER_RESPONSE_CODE.get(autorization_center_code),
                    ),
                }
            )

            return self.write(values)

        if transaction_status in PAYBOX_CODE_RESPONSE:
            _logger.info(PAYBOX_CODE_RESPONSE[transaction_status])

            # Status code when the transaction is done
            if transaction_status == '00000':
                state = 'done'
                values['date'] = fields.Datetime.now()

            # Status code when the transaction is pending
            elif transaction_status == '99999':
                state = 'pending'

            # Status code when the transaction is canceled
            elif transaction_status == '00001':
                state = 'cancel'

            else:
                state = 'error'

            _logger.info("Validated Paybox payment for transaction %s: set as %s" % (self.reference, state))
            values.update({'state': state, 'state_message': PAYBOX_CODE_RESPONSE[transaction_status]})

        return self.write(values)
