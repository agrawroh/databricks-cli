# Databricks CLI
# Copyright 2017 Databricks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"), except
# that the use of services to which certain application programming
# interfaces (each, an "API") connect requires that the user first obtain
# a license for the use of the APIs from Databricks, Inc. ("Databricks"),
# by creating an account at www.databricks.com and agreeing to either (a)
# the Community Edition Terms of Service, (b) the Databricks Terms of
# Service, or (c) another written agreement between Licensee and Databricks
# for the use of the APIs.
#
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import click

from databricks_cli.click_types import OneOfOption
from databricks_cli.configure.config import profile_option, debug_option
from databricks_cli.tokens.api import TokensApi
from databricks_cli.utils import CONTEXT_SETTINGS, eat_exceptions, pretty_format
from databricks_cli.version import print_version_callback, version

@click.command(context_settings=CONTEXT_SETTINGS,
               short_help='Generate a new token.')
@click.option('--token-type', '-t', required=True,
              type=click.Choice(['aad', 'databricks']),
              help='Type of token to be generated.')
@click.option('--resource-id', '-r', required=True,
              help='AzureDatabricks Application ID.')
@click.option('--client-id', '-c', required=True,
              help='Azure Application/Client ID.')
@click.option('--client-secret', '-s', required=True,
              help='Azure Application Authentication Secret String.')
@click.option('--callback-port', '-p', required=True, type=int,
              help='Azure Application Callback Port Number.')
@click.option('--out-file', '-o', required=False,
              help='Path of the file where token shall be written.')
@debug_option
@profile_option
@eat_exceptions #NOQA
def create_token_cli(token_type, resource_id, client_id, client_secret,
                     callback_port, out_file):
    """
    Generate New Tokens.
    """
    if (token_type == 'aad'):
        print('Generating a new AAD token...')
        TokensApi().generate_new_aad_token(resource_id, client_id, client_secret,
                                           callback_port, out_file)
    else:
        print('This feature is not yet supported.')

@click.command(context_settings=CONTEXT_SETTINGS,
               short_help='Generate a new token.')
@click.option('--token-type', '-t', required=True,
              type=click.Choice(['aad', 'databricks']),
              help='Type of token to be generated.')
@click.option('--resource-id', '-r', required=True,
              help='AzureDatabricks Application ID.')
@click.option('--client-id', '-c', required=True,
              help='Azure Application/Client ID.')
@click.option('--client-secret', '-s', required=True,
              help='Azure Application Authentication Secret String.')
@click.option('--refresh-token', '-f', required=True,
              help='Azure AAD OBO Refresh Token String.')
@click.option('--out-file', '-o', required=False,
              help='Path of the file where token shall be written.')
@debug_option
@profile_option
@eat_exceptions #NOQA
def renew_token_cli(token_type, resource_id, client_id, client_secret,
                    refresh_token, out_file):
    """
    Renew/Refresh previously generated tokens.
    """
    if (token_type == 'aad'):
        print('Refreshing the given AAD token...')
        TokensApi().refresh_aad_token(resource_id, client_id, client_secret,
                                      refresh_token, out_file)
    else:
        print('This feature is not yet supported.')

@click.group(context_settings=CONTEXT_SETTINGS,
             short_help='Utility to interact with libraries.')
@click.option('--version', '-v', is_flag=True, callback=print_version_callback,
              expose_value=False, is_eager=True, help=version)
@debug_option
@profile_option
@eat_exceptions
def tokens_group():
    """
    Utility to create/renew tokens.

    These tokens can be used to make API calls,
    (https://docs.azuredatabricks.net/api/latest/authentication.html).
    """
    pass

tokens_group.add_command(create_token_cli, name='create')
tokens_group.add_command(renew_token_cli, name='renew')
