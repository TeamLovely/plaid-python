try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin
import requests
import pytest
import json
from mock import patch

from plaid.client import Client, require_access_token, PermissionError


# Unit Tests
def test_require_access_token_decorator():
    class TestClass(object):
        access_token = 'foo'

        @require_access_token
        def some_func(self):
            return True

    obj = TestClass()
    obj.some_func()


def test_require_access_token_decorator_raises():
    class TestClass(object):
        access_token = None

        @require_access_token
        def some_func(self):
            return True

    obj = TestClass()
    with pytest.raises(PermissionError):
        obj.some_func()


def test_dev_url():
    assert Client('myclientid', 'mysecret', 'token').url == 'https://tartan.plaid.com'


def test_prod_url():
    assert Client('myclientid', 'mysecret', 'token', url='https://api.plaid.com').url == 'https://api.plaid.com'


def test_add_user():
    mock_response = requests.Response()
    mock_response._content = b'{"access_token":"foo_token"}'
    mock_response.status_code = 200

    client = Client('myclientid', 'mysecret')
    account_type = 'bofa'
    username = 'foo'
    password = 'bar'

    expected_post_data = {
        'type': 'bofa',
        'username': 'foo',
        'password': 'bar',
        'client_id': client.client_id,
        'secret': client.secret
    }
    expected_request_url = urljoin(client.url, client.endpoints['connect_user'])

    with patch('requests.post') as mock_requests_post:
        mock_requests_post.return_value = mock_response

        client.add_user(account_type, username, password)

        assert client.access_token == 'foo_token'
        mock_requests_post.assert_called_once_with(expected_request_url, expected_post_data)


def test_connect_step():
    client = Client('myclientid', 'mysecret', 'token')
    options = {'foo': 'bar'}

    expected_post_data = {
        'mfa': 'foo',
        'access_token': client.access_token,
        'client_id': client.client_id,
        'type': 'bofa',
        'secret': client.secret,
        'options': json.dumps(options)
    }
    expected_request_url = urljoin(client.url, client.endpoints['connect_step'])

    with patch('requests.post') as mock_requests_post:
        client.connect_step('bofa', 'foo', options=options)

        mock_requests_post.assert_called_once_with(expected_request_url, expected_post_data)


def test_step_requires_access_token():
    client = Client('myclientid', 'mysecret')
    with pytest.raises(PermissionError):
        client.connect_step('bofa', 'foo')


def test_delete_user():
    client = Client('myclientid', 'mysecret', 'token')

    expected_url = urljoin(client.url, client.endpoints['connect_user'])
    expected_request_data = {
        'client_id': client.client_id,
        'secret': client.secret,
        'access_token': client.access_token
    }

    with patch('requests.delete') as mock_requests_delete:
        client.delete_user()

        mock_requests_delete.assert_called_once_with(expected_url, data=expected_request_data)


def test_delete_user_requires_access_token():
    client = Client('myclientid', 'mysecret')
    with pytest.raises(PermissionError):
        client.delete_user('bofa', 'foo')


def test_update_user():
    client = Client('myclientid', 'mysecret', 'token')
    username = 'foo_username'
    password = 'foo_password'

    expected_url = urljoin(client.url, client.endpoints['connect_user'])
    expected_request_data = {
        'client_id': client.client_id,
        'secret': client.secret,
        'access_token': client.access_token,
        'username': username,
        'password': password
    }

    with patch('requests.patch') as mock_requests_patch:
        client.update_user(username, password)

        mock_requests_patch.assert_called_once_with(expected_url, expected_request_data)


def test_update_user_requires_access_token():
    client = Client('myclientid', 'mysecret')
    with pytest.raises(PermissionError):
        client.update_user('foo', 'bar')


def test_transactions():
    client = Client('myclientid', 'mysecret', 'token')
    options = {'foo': 'bar'}

    expected_url = urljoin(client.url, client.endpoints['transactions'])
    expected_request_data = {
        'client_id': client.client_id,
        'secret': client.secret,
        'access_token': client.access_token,
        'options': json.dumps(options)
    }

    with patch('requests.post') as mock_requests_post:
        client.transactions(options=options)

        mock_requests_post.assert_called_once_with(expected_url, expected_request_data)


def test_transactions_requires_access_token():
    client = Client('myclientid', 'mysecret')
    with pytest.raises(PermissionError):
        client.transactions()


def test_balance():
    client = Client('myclientid', 'mysecret', 'token')

    expected_url = urljoin(client.url, client.endpoints['balance'])
    expected_request_data = {
        'client_id': client.client_id,
        'secret': client.secret,
        'access_token': client.access_token
    }

    with patch('requests.get') as mock_requests_get:
        client.balance()
        mock_requests_get.assert_called_once_with(expected_url, data=expected_request_data)


def test_balance_requires_access_token():
    client = Client('myclientid', 'mysecret')
    with pytest.raises(PermissionError):
        client.balance()


def test_categories():
    client = Client('myclientid', 'mysecret')
    expected_url = urljoin(client.url, client.endpoints['categories'])

    with patch('requests.get') as mock_requests_get:
        client.categories()
        mock_requests_get.assert_called_once_with(expected_url)


def test_category():
    client = Client('myclientid', 'mysecret')
    expected_url = urljoin(client.url, client.endpoints['category']).format('1')

    with patch('requests.get') as mock_requests_get:
        client.category(1)
        mock_requests_get.assert_called_once_with(expected_url)


def test_institutions():
    client = Client('myclientid', 'mysecret')
    expected_url = urljoin(client.url, client.endpoints['institutions'])

    with patch('requests.get') as mock_requests_get:
        client.institutions()
        mock_requests_get.assert_called_once_with(expected_url)


def test_institution():
    client = Client('myclientid', 'mysecret')
    expected_url = urljoin(client.url, client.endpoints['institution']).format('1')

    with patch('requests.get') as mock_requests_get:
        client.institution(1)
        mock_requests_get.assert_called_once_with(expected_url)

