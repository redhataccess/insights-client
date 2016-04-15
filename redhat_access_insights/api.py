'''
Public API module to Insights client functions
'''

from insights.connection import InsightsConnection, InsightsConnectionError
from insights.constants import InsightsConstants as constants
from insights import parse_config_file, try_register, set_up_logging


class API(object):
    def __init__(self,
                 conf=constants.default_conf_file):
        '''
        Create API instance

        Parameters:
            conf - if specified, load a custom Insights
                configuration file at this path.
                By default, this is
                /etc/redhat-access-insights/redhat-access-insights.conf

        Returns:
            Instance of API object
        '''
        # stub the options object
        self.options = lambda: None
        # keep logging quiet for the API functions
        setattr(self.options, 'to_stdout', False)
        setattr(self.options, 'verbose', False)
        setattr(self.options, 'silent', True)
        setattr(self.options, 'quiet', False)
        self.config = parse_config_file(conf)
        set_up_logging(self.config, self.options)

    def register(self,
                 display_name=None,
                 group=None):
        '''
        Attempt to register this system with the Insights service.

        Parameters:
            display_name - desired name for this
                host in the Insights UI (none by default)
            group - desired grouping for this
                host in the Insights UI (none by default)

        Returns:
            Tuple of a locally generated message, message
            from the API (if any), and one of the following

            0: registration successful
            1: registration failed

        Example output:
            ('This host has already been registered.', None, 1)

        Raises:
            InsightsConnectionError
        '''
        setattr(self.options, 'display_name', display_name)
        setattr(self.options, 'group', group)
        return try_register(self.options, self.config)

    def test_connection(self):
        '''
        Test the network configuration, making sure a
        connection to the Insights service can be established.

        Parameters:
            None

        Returns:
            Tuple of connection test logging output,
            and one of the following

            0: connection test successful
            1: connection test had one or more failures

        Raises:
            InsightsConnectionError
        '''
        return InsightsConnection(self.config).test_connection()
