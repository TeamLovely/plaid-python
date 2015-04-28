from urllib.parse import urljoin
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


def test_user_income():
    client = Client('myclientid', 'mysecret', 'mytoken')
    options = {
        'gte': '2015-12-12',
        'lte': '2014-12-12'
    }
    mock_response_data = {
        'accounts': [],
        'transactions': [
            {'amount': 100},
            {'amount': -100},
            {'amount': -100},
            {'amount': 100},
            {'amount': -100},
            {'amount': 100},
            {'amount': 100},
            {'amount': -100},
            {'amount': 100},
            {'amount': 100},
        ]
    }
    mock_response = requests.Response()
    mock_response._content = json.dumps(mock_response_data).encode('utf-8')

    expected_url = urljoin(client.url, client.endpoints['transactions'])
    expected_request_data = {
        'secret': client.secret,
        'client_id': client.client_id,
        'access_token': client.access_token,
        'options': json.dumps(options)
    }

    with patch('requests.post') as mock_requests_post:
        mock_requests_post.return_value = mock_response

        assert client.user_income(options=options) == 400
        mock_requests_post.assert_called_once_with(expected_url, expected_request_data)


"""
Integration Tests. These tests hit the real Plaid developer API to make sure everything still works.
There are no charges for requests to the dev API.
"""
question_mfa_type = 'bofa'
code_mfa_type = 'chase'
no_mfa_type = 'amex'
test_id = 'test_id'
test_secret = 'test_secret'
test_username = 'plaid_test'
test_good_password = 'plaid_good'
test_locked_password = 'plaid_locked'


def test_locked_password():
    account_type = no_mfa_type
    client = Client(test_id, test_secret)
    response = client.add_user(account_type, test_username, test_locked_password)

    assert not response.ok
    assert 'code' in response.json()
    assert 'message' in response.json()
    assert 'resolve' in response.json()


def test_code_mfa_flow():
    account_type = code_mfa_type
    client = Client(test_id, test_secret)
    response1 = client.add_user(account_type, test_username, test_good_password)
    response2 = client.connect_step(account_type, 1234)

    assert response1.ok
    assert response2.ok
    assert 'transactions' not in response1.json()
    assert 'accounts' not in response1.json()
    assert 'mfa' in response1.json()
    assert client.access_token == 'test_{}'.format(account_type)
    assert 'transactions' in response2.json()
    assert 'accounts' in response2.json()
    assert 'mfa' not in response2.json()


def test_question_mfa_flow():
    account_type = question_mfa_type
    client = Client(test_id, test_secret, 'test_chase')
    response1 = client.add_user(account_type, test_username, test_good_password)
    response2 = client.connect_step(account_type, 'again')
    response3 = client.connect_step(account_type, 'tomato')

    assert response1.ok
    assert response2.ok
    assert response3.ok
    assert 'mfa' in response1.json()
    assert 'mfa' in response2.json()
    assert 'mfa' not in response3.json()
    assert 'transactions' in response3.json()
    assert 'accounts' in response3.json()


def test_no_mfa_flow():
    account_type = no_mfa_type
    client = Client(test_id, test_secret)
    response1 = client.add_user(account_type, test_username, test_good_password)

    assert response1.ok
    assert 'mfa' not in response1.json()
    assert 'transactions' in response1.json()
    assert 'accounts' in response1.json()


def test_update_user_endpoint():
    client = Client(test_id, test_secret, 'test_amex')
    response = client.update_user(test_username, test_good_password)

    assert response.ok
    assert 'accounts' in response.json()
    assert 'transactions' in response.json()


def test_delete_user_endpoint():
    client = Client(test_id, test_secret, 'test_amex')
    response = client.delete_user()

    assert response.ok
    assert 'message' in response.json()


def test_transactions_endpoint():
    client = Client(test_id, test_secret, 'test_amex')
    response = client.transactions()

    assert response.ok
    assert 'accounts' in response.json()
    assert 'transactions' in response.json()


def test_balance_endpoint():
    client = Client(test_id, test_secret, 'test_amex')
    response = client.balance()

    assert response.ok
    assert 'accounts' in response.json()
    assert 'transactions' not in response.json()


def test_categories_endpoint():
    client = Client(test_id, test_secret, 'test_amex')
    response = client.categories()

    assert response.ok
    assert isinstance(response.json(), list)
    first_category = response.json()[0]
    assert 'hierarchy' in first_category
    assert 'type' in first_category
    assert 'id' in first_category


def test_category_endpoint():
    client = Client(test_id, test_secret, 'test_amex')
    response = client.category(17001013)

    assert response.ok
    category = response.json()
    assert 'hierarchy' in category
    assert 'type' in category
    assert 'id' in category
