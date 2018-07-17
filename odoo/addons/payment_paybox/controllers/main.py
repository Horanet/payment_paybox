# coding: utf8

import werkzeug

from odoo import http
from odoo.http import request


class SystemPayController(http.Controller):

    @http.route('/payment/paybox/ipn', type='http', methods=['GET'], auth='public', csrf=False)
    def paybox_ipn(self, **kw):
        """Route called after a transaction with Paybox

        :param kw: dict that contains GET values received from Paybox
        :return: response object
        """

        request.env['payment.transaction'].form_feedback(kw, 'paybox')

        return ''

    @http.route('/payment/paybox/dpn', type='http', methods=['GET'], auth='public', csrf=False)
    def paybox_dpn(self, **kw):
        """Route called when return on the shop

        :param kw: dict that contains GET values received from Paybox
        :return: Redirection to the home page
        """

        request.env['payment.transaction'].form_feedback(kw, 'paybox')
        return_url = kw.get('return_url', '/')

        return werkzeug.utils.redirect(return_url)
