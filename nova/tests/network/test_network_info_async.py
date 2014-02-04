# Copyright 2014 Juniper Networks, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
This script reproduces the deadlock problem with nova-compute use of
NetworkInfoAsyncWrapper.

nova/cmd/__init__.py does eventlet.monkey_patch() which causes locks to have
greenthread ownership (vs native threading).

nova uses a GreenPool() to receive requests via
nova.openstack.common.threadgroup
"""

import eventlet
eventlet.monkey_patch(os=False)

from nova.network import model
from nova.openstack.common import log as logging
from nova import test
from oslo.config import cfg
import threading

CONF = cfg.CONF
CONF.debug = True

LOG = logging.getLogger(__name__)


class NetworkInfoAsyncUser(object):
    def __init__(self, testcase):
        self._ninfo = None
        self._test = testcase

    def create(self):
        def async_wrapper():
            print("current thread: %s" % threading.current_thread())
            LOG.debug(" *** Lock access *** ")
            return list()

        self._ninfo = model.NetworkInfoAsyncWrapper(async_wrapper)

    def log_and_str(self):
        LOG.debug('NetworkInfo: %(network_info)s',
                  {'network_info': self._ninfo})
# The following does not reproduce the problem:
#       LOG.debug('NetworkInfo: %s' % (self._ninfo))
        self._test.assertTrue('NetworkInfoAsyncWrapper' in str(self._ninfo))


class NetworkInfoAsyncWrapperTests(test.NoDBTestCase):
    def setUp(self):
        super(NetworkInfoAsyncWrapperTests, self).setUp()
        logging.setup('test_network_info_async')

    def test_async_wrapper_str(self):
        def run_test(testcase):
            print("current thread: %s" % threading.current_thread())
            test_case = NetworkInfoAsyncUser(testcase)
            test_case.create()
            test_case.log_and_str()

        pool = eventlet.greenpool.GreenPool()
        pool.spawn(run_test, self)
        pool.waitall()
