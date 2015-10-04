from mechanize import Browser, ControlNotFoundError
from retry import retry
import re


class FishtestError(Exception):
    pass


class Fishtest():

    def __init__(self):
        self.browser = Browser()

    @retry(tries=3, delay=1, backoff=2)
    def login(self, username, password):
        """Login to Fishtest

        Try to login with passed credentials, upon success we receive the
        'new test' form and keep it in self.browser for later submit.
        """
        try:
            br = self.browser
            br.open('http://tests.stockfishchess.org/tests/run')
            br.select_form(nr=0)
            br["username"] = username
            br["password"] = password
            br.submit()
            br.select_form(nr=0)

            # Ok, now we should have received the 'run' form, let's verify
            # if all was ok accessing one of the returned fields.
            br["test_type"]

        except ControlNotFoundError:
            raise FishtestError('Failed login to Fishtest')
        except:
            raise FishtestError('Error while accessing Fishtest')

    @retry(tries=3, delay=1, backoff=2)
    def submit_test(self, content):
        """Submit test

        Should be done after login so that we already have received the 'new'
        form from Fishtest.
        """
        map = {'ref'       : 'test-branch',
               'bench_head': 'test-signature',
               'master'    : 'base-branch',
               'bench_base': 'base-signature',
               'repo_url'  : 'tests-repo',
               'message'   : 'run-info'}

        if not all(k in content.keys() for k in map.keys()):
            raise FishtestError('Map error')

        try:
            br = self.browser
            for k in map.keys():
                br[map[k]] = content[k]

            data = br.submit().get_data()  # Here we go!

        except ControlNotFoundError:
            raise FishtestError('Missing fields in test submit form')
        except:
            raise FishtestError('Error while submitting test')

        # After a successful submit, Fishtest returns the main tests view.
        # Look for the newly created test there and return the test id.
        p = r'<a href="/tests/view/(\w+)">{ref}</a>.*?/compare/{master}\.\.\.{sha}'
        p = p.format(ref=content['ref'],
                     master=content['master_sha'][:7],
                     sha=content['ref_sha'][:7])

        test_id = re.search(p, data, re.MULTILINE | re.DOTALL)
        if not test_id:
            raise FishtestError('Unable to find test_id')

        return test_id.group(1)
