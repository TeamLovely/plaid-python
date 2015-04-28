import json
import datetime
import requests
try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin


class PermissionError(OSError):
    pass


def require_access_token(func):
    def inner_func(self, *args, **kwargs):
        if not self.access_token:
            raise PermissionError('`{}` method requires `access_token`'.format(func.__name__))
        return func(self, *args, **kwargs)
    return inner_func


class Client(object):
    """
    Python Plain API client https://plaid.com/docs/
    """

    ACCOUNT_TYPES = (
        ('amex', 'American Express',),
        ('bofa', 'Bank of America',),
        ('capone360', 'Capital One 360',),
        ('schwab', 'Charles Schwab',),
        ('chase', 'Chase',),
        ('citi', 'Citi',),
        ('fidelity', 'Fidelity',),
        ('pnc', 'PNC',),
        ('svb', 'Silicon Vally Bank',),
        ('us', 'US Bank',),
        ('usaa', 'USAA',),
        ('wells', 'Wells Fargo',),
    )

    endpoints = {
        'balance': '/balance',
        'categories': '/categories',
        'category': '/categories/{}',
        'connect_user': '/connect',
        'connect_step': '/connect/step',
        'institutions': '/institutions',
        'institution': '/institutions/{}',
        'transactions': '/connect/get'
    }

    def __init__(self, client_id, secret, access_token=None, url='https://tartan.plaid.com'):
        """
        `client_id`     str     Your Plaid client ID
        `secret`        str     Your Plaid secret
        `access_token`  str     Access token if you already have one
        """
        self.client_id = client_id
        self.secret = secret
        self.access_token = access_token
        self.url = url

    def add_user(self, account_type, username, password, options=None):
        """
        Add a bank account user/login to Plaid and receive an access token
        unless a 2nd level of authentication is required, in which case
        an MFA (Multi Factor Authentication) question(s) is returned

        `account_type`  str     The type of bank account you want to sign in
                                to, must be one of the keys in `ACCOUNT_TYPES`
        `username`      str     The username for the bank account you want to
                                sign in to
        `password`      str     The password for the bank account you want to
                                sign in to
        `email`         str     The email address associated with the bank
                                account
        `options`       dict
            `webhook`   str         URL to hit once the account's transactions
                                    have been processed
            `mfa_list`  boolean     List all available MFA (Multi Factor
                                    Authentication) options
        """
        if options is None:
            options = {}
        url = urljoin(self.url, self.endpoints['connect_user'])

        data = {
            'client_id': self.client_id,
            'secret': self.secret,
            'type': account_type,
            'username': username,
            'password': password
        }

        if options:
            data['options'] = json.dumps(options)

        response = requests.post(url, data)

        if response.ok:
            json_data = response.json()
            if 'access_token' in json_data:
                self.access_token = json_data['access_token']

        return response

    @require_access_token
    def connect_step(self, account_type, mfa, options=None):
        """
        Perform a MFA (Multi Factor Authentication) step, requires
        `access_token`

        `account_type`  str     The type of bank account you're performing MFA
                                on, must match what you used in the `connect`
                                call
        `mfa`           str     The MFA answer, e.g. an answer to q security
                                question or code sent to your phone, etc.
        `options`       dict
            `send_method`   dict    The send method your MFA answer is for,
                                    e.g. {'type': Phone'}, should come from
                                    the list from the `mfa_list` option in
                                    the `connect` call
        """
        if options is None:
            options = {}
        url = urljoin(self.url, self.endpoints['connect_step'])

        data = {
            'client_id': self.client_id,
            'secret': self.secret,
            'access_token': self.access_token,
            'type': account_type,
            'mfa': mfa
        }

        if options:
            data['options'] = json.dumps(options)

        return requests.post(url, data)

    @require_access_token
    def update_user(self, username, password):
        """
        Update a Plaid user's bank authentication information, requires `access_token`

        `username`  str     The new username for this user
        `password`  str     The new password for this user
        """
        url = urljoin(self.url, self.endpoints['connect_user'])

        data = {
            'client_id': self.client_id,
            'secret': self.secret,
            'access_token': self.access_token,
            'username': username,
            'password': password
        }

        return requests.patch(url, data)

    @require_access_token
    def delete_user(self):
        """
        Delete user from Plaid, requires `access_token`
        """
        url = urljoin(self.url, self.endpoints['connect_user'])

        data = {
            'client_id': self.client_id,
            'secret': self.secret,
            'access_token': self.access_token
        }

        return requests.delete(url, data=data)

    @require_access_token
    def transactions(self, options=None):
        """
        Fetch a list of transactions, requires `access_token`

        `options`   dict
            `pending`   bool        default is false. If set to true, transactions from account activities that have
                                    not yet posted to the account will be returned. Pending transactions will generally
                                    show up as posted within one to three business days, depending on the type of
                                    transaction.
            `account`   str         Collect transactions for a specific account only, using an `account_id` returned
                                    from the original `add_user` submission.
            `gte`       date        Collect all recent transactions since and including the given date.
            `lte`       date        Collect all transactions up to and including the given date. Can be used with gte
                                    to define a range.
        """
        if options is None:
            options = {}
        url = urljoin(self.url, self.endpoints['transactions'])

        data = {
            'client_id': self.client_id,
            'secret': self.secret,
            'access_token': self.access_token
        }

        if options:
            data['options'] = json.dumps(options)

        return requests.post(url, data)

    def categories(self):
        """
        Fetch all categories
        """
        url = urljoin(self.url, self.endpoints['categories'])
        return requests.get(url)

    def category(self, category_id):
        """
        Fetch a specific category

        `category_id`   str     Category id to fetch
        """
        url = urljoin(self.url, self.endpoints['category']).format(category_id)
        return requests.get(url)

    @require_access_token
    def balance(self, options=None):
        """
        Fetch the real-time balance of the user's accounts, requires `access_token`

        """
        if options is None:
            options = {}
        url = urljoin(self.url, self.endpoints['balance'])
        data = {
            'client_id': self.client_id,
            'secret': self.secret,
            'access_token': self.access_token
        }
        if options:
            data['options'] = json.dumps(options)

        return requests.get(url, data=data)

    def institutions(self):
        """
        Fetch the available institutions
        """
        url = urljoin(self.url, self.endpoints['institutions'])
        return requests.get(url)

    def institution(self, institution_id):
        """
        Fetch a specific institution

        `institution_id`   str     Institution id to fetch
        """
        url = urljoin(self.url, self.endpoints['institution']).format(institution_id)
        return requests.get(url)

    @require_access_token
    def user_income(self, options=None):
        """
        The amount of income a user has had within some date range across all accounts we have access to. Requires
        `access_token`. Returns the sum of all credit transactions for the last twelve months. Debit transactions are
        ignored.

        `options`   dict    Same options as `transactions`
        """
        if options is None:
            options = {
                # One year ago in isoformat
                'gte': (datetime.datetime.now() - datetime.timedelta(365)).date().isoformat()
            }

        transactions = self.transactions(options=options).json()['transactions']

        total_income = 0
        for transaction in transactions:
            # Credits to the account are negative. Ignore debits from the account, which are positive.
            if transaction['amount'] < 0:
                total_income -= transaction['amount']

        return total_income
