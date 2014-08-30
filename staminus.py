"""
    Staminus API Python Library

    http://support.staminus.net/index.php?action=artikel&cat=11&id=19&artlang=en

    Author: Benton Snyder
    Date: 8/30/2014
"""
import requests
import requests.auth


class Staminus:
    def __init__(self, client_id, client_secret, redirect_uri, username, password):
        """ Public Constructor

        Parameters:
            client_id: str staminus api client password
            client_secret: str staminus api client secret
            redirect_uri: str staminus redirect uri
            username: str staminus account username
            password: str staminus account password
        """
        self.USERNAME = username
        self.TOKEN = self.get_auth_token(client_id, client_secret, redirect_uri, password)

        if not self.TOKEN:
            return None


    def get_auth_token(self, client_id, client_secret, redirect_uri, password):
        """ Get Auth Token

            Fetches OAUTH2 Token that will provide authentication for member functions.

        Parameters:
            client_id: str staminus api client password
            client_secret: str staminus api client secret
            redirect_uri: str staminus redirect uri
            password: str staminus account password
        Returns
            str oath2 access token 
        """
        try:
            client_auth = requests.auth.HTTPBasicAuth(client_id, client_secret)
            post_data = {
                "redirect_uri": redirect_uri,
                'username': self.USERNAME, 
                'grant_type': 'password', 
                'password': password
            }

            response = requests.post("https://api.staminus.net/token.php", auth=client_auth, data=post_data)

            if response.status_code is not 200:
                raise Exception("HTTP returned error %d" % response.status_code)

            jsonstr = response.json()
            if 'access_token' not in jsonstr:
                raise Exception("Could not find access_token in response: %s" % jsonstr)

            return jsonstr['access_token']
        except Exception as ex:
            print "Failed to retrieve Access Token: %s" % ex
            return False


    def _api_query(self, querystr):
        """ Query Staminus' API

            HTTP Get queries Staminus API with specified URL encoded string.

        Parameters:
            querystr: str url-encoded get variables
        Returns:
            str json-encoded response
        """
        try:
            response = requests.get("https://api.staminus.net/?%s&accountID=%s&access_token=%s" % (querystr, self.USERNAME, self.TOKEN))
            if response.status_code is not 200:
                raise Exception("HTTP returned error %d" % response.status_code)

            return response.json()
        except Exception as ex:
            print "API query failed: %s" % ex
            return False


    def get_servers(self):
        """ Get Servers

            Fetches account's servers listing.

        Returns:
            str json-encoded response 
        """
        return self._api_query('servers=1')


    def get_attack_logs(self, server_id):
        """ Get Attack Logs

            Fetches DDoS records for specified server.

        Parameters:
            server_id: str server id
        Returns:
            str json-encoded response 
        """        
        return self._api_query('ddos_report=1&serverID=%s' % server_id)


    def get_secure_ports(self):
        """ Get Secure Ports

            Fetches account's secure ports listing.

        Returns:
            str json-encoded response 
        """            
        return self._api_query('get_all_Secureports=1')


    def get_secure_port(self, secureport_id):
        """ Get Secure Port

            Fetches all blocks for specified secure port.

        Parameters:
            secureport_id: str secure port id
        Returns:
            str json-encoded response 
        """   
        return self._api_query('secureport_blocks=1&secureIP=%s' % secureport_id)


    def clear_secure_ports(self, secureport_id):
        """ Clear Secure Ports

            Clears all blocks for specified secure port.

        Parameters:
            secureport_id: str secure port id
        Returns:
            str json-encoded response 
        """           
        return self._api_query('secureport_blocks_clear=1&secureIP=%s' % secureport_id)


    def clear_secure_port(self, secureport_id, block_id):
        """ Clear Secure Port

            Clears specified block for specified secure port.

        Parameters:
            secureport_id: str secure port id
            block_id: str block id
        Returns:
            str json-encoded response 
        """           
        return self._api_query('secureport_blocks_clear_specific=1&secureIP=%s&blockID=%s' % (secureport_id, block_id))
