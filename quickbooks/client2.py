try:  # Python 3
    import http.client as httplib
    from urllib.parse import parse_qsl
except ImportError:  # Python 2
    import httplib
    from urlparse import parse_qsl

import textwrap
import json
import os
from .exceptions import QuickbooksException, SevereException, AuthorizationException
import base64
from collection import namedtuple

try:
    from rauth import OAuth1Session, OAuth1Service, OAuth2Session, OAuth2Service
except ImportError:
    print("Please import Rauth:\n\n")
    print("http://rauth.readthedocs.org/en/latest/\n")
    raise

try:
    import requests
except ImportError:
    print("Please pip install request:\n\n")
    print("http://docs.python-requests.org/en/master/\n")
    raise

ConfigProperty = namedtuple("Config", 'sandbox production')

class QuickBooks(object):
    """A wrapper class around Python's Rauth module for Quickbooks the API"""

    scopes = {
        'accounting': 'com.intuit.quickbooks.accounting',
        'payments': 'com.intuit.quickbooks.payment'
    }

    access_token = ''
    access_token_secret = ''
    consumer_key = ''
    consumer_secret = ''
    company_id = 0
    callback_url = ''
    session = None
    sandbox = False
    minorversion = None
    oauth2 = False
    scope = scopes['accounting']
    client_id = ''
    client_secret = ''
    redirect_url = ''
    response_type = 'code'
    code = ''

    qbService = None

    sandbox_api_url_v3 = "https://sandbox-quickbooks.api.intuit.com/v3"
    api_url_v3 = "https://quickbooks.api.intuit.com/v3"

    request_token_url = "https://oauth.intuit.com/oauth/v1/get_request_token"
    access_token_url = "https://oauth.intuit.com/oauth/v1/get_access_token"

    authorize_url = "https://appcenter.intuit.com/Connect/Begin"

    current_user_url = "https://appcenter.intuit.com/api/v1/user/current"

    disconnect_url = "https://appcenter.intuit.com/api/v1/connection/disconnect"
    reconnect_url = "https://appcenter.intuit.com/api/v1/connection/reconnect"

    request_token = ''
    request_token_secret = ''

    _BUSINESS_OBJECTS = [
        "Account", "Attachable", "Bill", "BillPayment",
        "Class", "CreditMemo", "Customer",
        "Department", "Deposit", "Employee", "Estimate", "Invoice",
        "Item", "JournalEntry", "Payment", "PaymentMethod",
        "Purchase", "PurchaseOrder", "RefundReceipt",
        "SalesReceipt", "TaxCode", "TaxService/Taxcode", "TaxRate", "Term",
        "TimeActivity", "Transfer", "Vendor", "VendorCredit"
    ]

    __instance = None
    __use_global = False

    # The discovery documents for Intuit's OpenID Connect service are located here:
    openid_discover_document_urls = ConfigProperty(
        sandbox = "https://developer.api.intuit.com/.well-known/openid_sandbox_configuration",
        production = "https://developer.api.intuit.com/.well-known/openid_configuration"
    )

    def __new__(cls, **kwargs):
        """
        If global is disabled, don't set global client instance.
        """
        if QuickBooks.__use_global:
            if QuickBooks.__instance is None:
                QuickBooks.__instance = object.__new__(cls)
            instance = QuickBooks.__instance
        else:
            instance = object.__new__(cls)

        if 'consumer_key' in kwargs:
            instance.consumer_key = kwargs['consumer_key']

        if 'consumer_secret' in kwargs:
            instance.consumer_secret = kwargs['consumer_secret']

        if 'access_token' in kwargs:
            instance.access_token = kwargs['access_token']

        if 'access_token_secret' in kwargs:
            instance.access_token_secret = kwargs['access_token_secret']

        if 'company_id' in kwargs:
            instance.company_id = kwargs['company_id']

        if 'callback_url' in kwargs:
            instance.callback_url = kwargs['callback_url']

        if 'sandbox' in kwargs:
            instance.sandbox = kwargs['sandbox']

        if 'minorversion' in kwargs:
            instance.minorversion = kwargs['minorversion']

        if 'oauth2' in kwargs:
            instance.oauth2 = kwargs['oauth2']

        if 'scope' in kwargs:
            instance.scope = kwargs['scope']

        if 'client_id' in kwargs:
            instance.client_id = kwargs['client_id']

        if 'client_secret' in kwargs:
            instance.client_secret = kwargs['client_secret']

        if 'redirect_url' in kwargs:
            instance.redirect_url = kwargs['redirect_url']

        if 'response_type' in kwargs:
            instance.response_type = kwargs['response_type']

        if 'code' in kwargs:
            instance.code = kwargs['code']

        return instance

    @classmethod
    def get_instance(cls):
        return cls.__instance

    @classmethod
    def disable_global(cls):
        """
        Disable use of singleton pattern.
        """
        QuickBooks.__use_global = False
        QuickBooks.__instance = None

    @classmethod
    def enable_global(cls):
        """
        Allow use of singleton pattern.
        """
        QuickBooks.__use_global = True

    def _drop(self):
        QuickBooks.__instance = None

    @property
    def openid_dicover_document_url(self):
        return self.openid_discover_document_urls.sandbox if self.sandbox else self.openid_discover_document_urls.production

    @property
    def openid_discovery_document(self):
        return requests.get(self.openid_discover_document_url, headers={"Accept" : "application/json"}).json()

    @property
    def authorization_endpoint(self):
        return self.openid_discovery_document["authorization_endpoint"]

    @property
    def token_endpoint(self):
        return self.openid_discovery_document["token_endpoint"]
    
    @property
    def issuer(self):
        return self.openid_discovery_document["issuer"]
    
    @property
    def revocation_endpoint(self):
        return self.openid_discovery_document["revocation_endpoint"]
    
    @property
    def userinfo_endpoint(self):
        return self.openid_discovery_document["userinfo_endpoint"]

    @property
    def response_types_supported(self):
        return self.openid_discovery_document["response_types_supported"]
    
    @property
    def api_url(self):
        if self.sandbox:
            return self.sandbox_api_url_v3
        else:
            return self.api_url_v3

    def create_session(self):
        session = None
        if self.oauth2 and self.code and self.redirect_url:
            session = qbService.get_auth_session(
                data=dict(
                    code=self.code,
                    redirect_url=self.redirect_url
                ))
        elif self.consumer_secret and self.consumer_key and self.access_token_secret and self.access_token:
            session = OAuth1Session(
                self.consumer_key,
                self.consumer_secret,
                self.access_token,
                self.access_token_secret,
            )
        if session:
            self.session = session
        else:
            raise QuickbooksException(
                "Quickbooks authentication fields not set. Cannot create session.")

        return self.session

    def get_authorize_url(self):
        """
        Returns the Authorize URL as returned by QB, and specified by OAuth 1.0a or 2.
        :return URI:
        """
        self.authorize_url = self.authorize_url[:self.authorize_url.find('?')] \
            if '?' in self.authorize_url else self.authorize_url
        if self.qbService is None:
            self.set_up_service()

        if self.oauth2:
            params = dict(
                scope = self.scope,
                response_type = self.response_type,
                redirect_url = self.redirect_url
            )
            return self.qbService.get_authorize_url(**params)
        else:
            response = self.qbService.get_raw_request_token(
                params={'oauth_callback': self.callback_url})

            oauth_resp = dict(parse_qsl(response.text))

            self.request_token = oauth_resp['oauth_token']
            self.request_token_secret = oauth_resp['oauth_token_secret']
            return self.qbService.get_authorize_url(self.request_token)

    def get_current_user(self):
        """Get data from the current user endpoint"""
        if self.oauth2:
            return self.make_request("GET", self.userinfo_endpoint)
        else:
            url = self.current_user_url
            result = self.make_request("GET", url)
            return result

    def get_report(self, report_type, qs=None):
        """Get data from the report endpoint"""
        if qs is None:
            qs = {}

        url = self.api_url + "/company/{0}/reports/{1}".format(self.company_id, report_type)
        result = self.make_request("GET", url, params=qs)
        return result

    def set_up_service(self):
        if self.oauth2:
            self.qbService = OAuth2Service(
                client_id=self.client_id,
                client_secret=self.client_secret,
                name='noblebankint',
                authorize_url=self.authorization_endpoint,
                access_token_url=self.token_endpoint,
                base_url=None
            )
        else:
            self.qbService = OAuth1Service(
                name=None,
                consumer_key=self.consumer_key,
                consumer_secret=self.consumer_secret,
                request_token_url=self.request_token_url,
                access_token_url=self.access_token_url,
                authorize_url=self.authorize_url,
                base_url=None
            )

    def get_access_tokens(self, oauth_verifier):
        """
        Wrapper around get_auth_session, returns session, and sets access_token and
        access_token_secret on the QB Object.
        :param oauth_verifier: the oauth_verifier as specified by OAuth 1.0a
        """
        if self.oauth2:
            data = dict(
                code = self.code,
                redirect_url = self.redirect_url
            )
            session = self.qbService.get_auth_session(data=data)
            return session
        else:
            session = self.qbService.get_auth_session(
                self.request_token,
                self.request_token_secret,
                data={'oauth_verifier': oauth_verifier})

            self.access_token = session.access_token
            self.access_token_secret = session.access_token_secret
            return session

    def disconnect_account(self):
        """
        Disconnect current account from the application
        :return:
        """
        url = self.revocation_endpoint if self.oauth2 else self.disconnect_url
        result = self.make_request("GET", url)
        return result

    def change_data_capture(self, entity_string, changed_since):
        url = self.api_url + "/company/{0}/cdc".format(self.company_id)

        params = {"entities": entity_string, "changedSince": changed_since}

        result = self.make_request("GET", url, params=params)
        return result

    def reconnect_account(self):
        """
        Reconnect current account by refreshing OAuth access tokens
        :return:
        """
        if self.oauth2:
            return None
        else:
            url = self.reconnect_url
            result = self.make_request("GET", url)
            return result

    def make_request(self, request_type, url, request_body=None, content_type='application/json',
                     params=None, file_path=None):

        if not params:
            params = {}

        if self.minorversion:
            params['minorversion'] = self.minorversion

        if not request_body:
            request_body = {}

        if self.session is None:
            self.create_session()
        headers = {
            'Content-Type': content_type,
            'Accept': 'application/json'
        }

        if file_path:
            attachment = open(file_path, 'rb')
            url = url.replace('attachable', 'upload')
            boundary = '-------------PythonMultipartPost'
            headers.update({
                'Content-Type': 'multipart/form-data; boundary=%s' % boundary,
                'Accept-Encoding': 'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
                'User-Agent': 'OAuth gem v0.4.7',
                'Accept': 'application/json',
                'Connection': 'close'
            })

            binary_data = str(base64.b64encode(attachment.read()).decode('ascii'))

            content_type = json.loads(request_body)['ContentType']

            request_body = textwrap.dedent(
                """
                --%s
                Content-Disposition: form-data; name="file_metadata_01"
                Content-Type: application/json

                %s

                --%s
                Content-Disposition: form-data; name="file_content_01"
                Content-Type: %s
                Content-Transfer-Encoding: base64

                %s

                --%s--
                """
            ) % (boundary, request_body, boundary, content_type, binary_data, boundary)

        req = self.session.request(
            request_type, url, True, self.company_id,
            headers=headers, params=params, data=request_body)

        if req.status_code == httplib.UNAUTHORIZED:
            raise AuthorizationException("Application authentication failed", detail=req.text)

        try:
            result = req.json()
        except:
            raise QuickbooksException("Error reading json response: {0}".format(req.text), 10000)

        if "Fault" in result:
            self.handle_exceptions(result["Fault"])
        elif not req.status_code == httplib.OK:
            raise QuickbooksException("Error returned with status code '{0}': {1}".format(
                req.status_code, req.text), 10000)
        else:
            return result

    def get_single_object(self, qbbo, pk):
        url = self.api_url + "/company/{0}/{1}/{2}/".format(self.company_id, qbbo.lower(), pk)
        result = self.make_request("GET", url, {})

        return result

    def handle_exceptions(self, results):
        # Needs to handle multiple errors
        for error in results["Error"]:

            message = error["Message"]

            detail = ""
            if "Detail" in error:
                detail = error["Detail"]

            code = ""
            if "code" in error:
                code = int(error["code"])

            if code >= 10000:
                raise SevereException(message, code, detail)
            else:
                raise QuickbooksException(message, code, detail)

    def create_object(self, qbbo, request_body, _file_path=None):
        self.isvalid_object_name(qbbo)

        url = self.api_url + "/company/{0}/{1}".format(self.company_id, qbbo.lower())
        results = self.make_request("POST", url, request_body, file_path=_file_path)

        return results

    def query(self, select):
        url = self.api_url + "/company/{0}/query".format(self.company_id)
        result = self.make_request("POST", url, select, content_type='application/text')

        return result

    def isvalid_object_name(self, object_name):
        if object_name not in self._BUSINESS_OBJECTS:
            raise Exception("{0} is not a valid QBO Business Object.".format(object_name))

        return True

    def update_object(self, qbbo, request_body, _file_path=None):
        url = self.api_url + "/company/{0}/{1}".format(self.company_id, qbbo.lower())
        result = self.make_request("POST", url, request_body, file_path=_file_path)

        return result

    def delete_object(self, qbbo, request_body, _file_path=None):
        url = self.api_url + "/company/{0}/{1}".format(self.company_id, qbbo.lower())
        result = self.make_request("POST", url, request_body, params={'operation': 'delete'}, file_path=_file_path)

        return result

    def batch_operation(self, request_body):
        url = self.api_url + "/company/{0}/batch".format(self.company_id)
        results = self.make_request("POST", url, request_body)

        return results

    def download_pdf(self, qbbo, item_id):
        url = self.api_url + "/company/{0}/{1}/{2}/pdf".format(
            self.company_id, qbbo.lower(), item_id)

        if self.session is None:
            self.create_session()

        headers = {
            'Content-Type': 'application/pdf',
            'Accept': 'application/pdf, application/json',
        }

        response = self.session.request("GET", url, True, self.company_id, headers=headers)

        if response.status_code != httplib.OK:
            try:
                result = response.json()
            except:
                raise QuickbooksException("Error reading json response: {0}".format(response.text), 10000)

            self.handle_exceptions(result["Fault"])
        else:
            return response.content
