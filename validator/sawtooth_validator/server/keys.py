# Copyright 2016, 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

import logging
import os

import sawtooth_signing as signing
from sawtooth_signing import CryptoFactory
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey
from sawtooth_validator.exceptions import LocalConfigurationError

LOGGER = logging.getLogger(__name__)


def load_identity_signer(key_dir, key_name):
    """Loads a private key from the key directory, based on a validator's
    identity.

    Args:
        key_dir (str): The path to the key directory.
        key_name (str): The name of the key to load.

    Returns:
        Signer: the cryptographic signer for the key
    """
    key_path = os.path.join(key_dir, f'{key_name}.priv')

    if not os.path.exists(key_path):
        raise LocalConfigurationError(f"No such signing key file: {key_path}")
    if not os.access(key_path, os.R_OK):
        raise LocalConfigurationError(f"Key file is not readable: {key_path}")

    LOGGER.info('Loading signing key: %s', key_path)
    try:
        with open(key_path, 'r') as key_file:
            private_key_str = key_file.read().strip()
    except IOError as e:
        raise LocalConfigurationError(f"Could not load key file: {str(e)}") from e

    try:
        private_key = Secp256k1PrivateKey.from_hex(private_key_str)
    except signing.ParseError as e:
        raise LocalConfigurationError(
            f"Invalid key in file {key_path}: {str(e)}"
        ) from e


    context = signing.create_context('secp256k1')
    crypto_factory = CryptoFactory(context)
    return crypto_factory.new_signer(private_key)
