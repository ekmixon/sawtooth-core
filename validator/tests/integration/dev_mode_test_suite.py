import unittest
import time
import os
from test_smoke import TestSmoke
from test_local_validation import TestLocalValidationErrors
from txnintegration.simcontroller import get_default_sim_controller
from txnintegration.validator_network_manager import ValidatorNetworkManager, \
    defaultValidatorConfig


def setUpModule():
    # setUpModule will be the first thing ran. This allows us to start up the
    # validators that we will use for all the following tests in the test suite
    print "Starting Validators for DevModeTestSuite"
    cfg = defaultValidatorConfig.copy()
    cfg['LedgerType'] = 'dev_mode'
    cfg['LocalValidation'] = True
    cfg['BlockWaitTime'] = 0
    vnm_config = cfg
    global sim
    sim = None
    try:
        # Start up validators using SimController
        sim = get_default_sim_controller(1, ledger_type='dev_mode')
        sim.do_genesis()
        sim.launch()
    except Exception as e:
        print "Something went wrong during setUp. {}".format(e)


def tearDownModule():
    # tearDownModule will be the last thing ran. This allows us to shut down
    # the validators and store the archives.
    print "Shutting Down Validators for DevModeTestSuite"
    if sim is not None:
        sim.shutdown(archive_name="DevModeTestSuiteArchive")
    else:
        print "No Validator data and logs to preserve"


class DevModeTestSuite(unittest.TestCase):
    def test_suite(self):
        # Add all test that will be run against the validators started in
        # setUpModule to the TestSuite. The following tests had to be changed
        # to work with validators they were not creating. This includes
        # hardcoding the urls into the tests. Also the tests will fail if they
        # are ran from within their TestClass. Therefore, I skipped those tests
        # unless the RUN_TEST_SUITES environment variable is set to 1. After
        # the test suite is written, it should be added to run_tests.
        suite = unittest.TestSuite()
        suite.addTest(
            TestLocalValidationErrors('test_local_validation_errors'))
        suite.addTest(TestSmoke('test_intkey_load_dev_mode'))
        runner = unittest.TextTestRunner()
        result = runner.run(suite)

        if len(result.failures) != 0:
            self.fail("DevModeTestSuite experienced failures.")

        if len(result.errors) != 0:
            self.fail("DevModeTestSuite experienced errors.")
