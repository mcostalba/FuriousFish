from mechanize import Browser, ControlNotFoundError
import re


class Fishtest():

    run_url = 'http://tests.stockfishchess.org/tests/run'

    def __init__(self):
        self.browser = Browser()

    def login(self, username, password):
        """Login to Fishtest

        Try to login with passed credentials, upon success we receive the
        'new test' form and keep it in self.browser for later submit.
        """
        br = self.browser
        br.open(self.run_url)

        # Mechanize fails loudly if a field is not found
        try:
           br.select_form(nr = 0)
           br["username"] = username
           br["password"] = password
           br.submit()
           br.select_form(nr = 0)

           # Ok, now we should have received the 'run' form, let's verify
           # if all was ok accessing one of the returned fields.
           br["test_type"]

        except ControlNotFoundError:
           return False
        return True

    def submit_test(self, content):
        """Submit test

        Should be done after login so that we already have received the 'new'
        form from Fishtest.
        """
        map = { 'ref'        : 'test-branch',
                'bench_head' : 'test-signature',
                'master'     : 'base-branch',
                'bench_base' : 'base-signature',
                'repo_url'   : 'tests-repo',
                'message'    : 'run-info'
              }

        if not all(k in content.keys() for k in map.keys()):
            return None, 'Fishtest: map error'

        br = self.browser
        try:
            for k in map.keys():
                br[map[k]] = content[k]

        except ControlNotFoundError:
           return None, 'Fishtest: missing fields in test submit form'

        data = br.submit().get_data() # Here we go!

        try:
            # After successful submit, Fishtest returns the main tests view.
            # Look for the newly created test there and return the test id.
            #
            # FIXME we pick the first one, can fail in case of an old test with
            # same ref and low prority.
            p = r'<a href="/tests/view/(\w+)">' + content['ref'] + r'</a>'
            test_id = re.search(p, data, re.MULTILINE|re.DOTALL)
            if not test_id:
                return None, 'Fishtest: unable to find test_id'

        except ControlNotFoundError:
           return None, 'Fishtest: test submit failed'

        return test_id.group(1), None
