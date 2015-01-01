"""

Staminus API Python Library

    http://support.staminus.net/index.php?action=artikel&cat=11&id=19&artlang=en

Author: Benton Snyder
Website: http://bensnyde.me
Created: 8/30/2014
Revised: 12/31/2014

"""
import requests
import json

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


    def _api_query(self, querystr, data=None):
        """ Query Staminus' API

            HTTP Get queries Staminus API with specified URL encoded string.

        Parameters:
            querystr: str url-encoded get variables
            *data: dictionary post data
        Returns:
            str json-encoded response
        """
        try:
            url = "https://api.staminus.net/?%s&accountID=%s&access_token=%s" % (querystr, self.USERNAME, self.TOKEN)

            if data:
                response = requests.post(url, data=json.dumps(data))
            else:
                response = requests.get(url)

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


    def get_secure_port(self, secureport_ip):
        """ Get Secure Port

            Fetches all blocks for specified secure port.

        Parameters:
            secureport_ip: str protected ip address
        Returns:
            str json-encoded response
        """
        return self._api_query('secureport_blocks=1&secureIP=%s' % secureport_ip)


    def clear_secure_ports(self, secureport_ip):
        """ Clear Secure Ports

            Clears all blocks for specified secure port.

        Parameters:
            secureport_ip: str protected ip address
        Returns:
            str json-encoded response
        """
        return self._api_query('secureport_blocks_clear=1&secureIP=%s' % secureport_ip)


    def clear_secure_port(self, secureport_ip, block_id):
        """ Clear Secure Port

            Clears specified block for specified secure port.

        Parameters:
            secureport_ip: str protected ip address
            block_id: str secureport block id
        Returns:
            str json-encoded response
        """
        return self._api_query('secureport_blocks_clear_specific=1&secureIP=%s&blockID=%s' % (secureport_ip, block_id))


    def set_secure_port(self, secureport_id=None, data=None):
        """ Set Secure Port

            Create a new Secure Port or update an existing Secure Port as specified by secureportID.

        Parameters:
            *secureport_id: str secureport id: specifying ID indicates update action, omitting indicates creation action
            *data:
                *ip: str IP the secureportID should protect
                *note: str notes for the secureport
                *description: str description for the secureport
                *status: int status [0|1]
                *email_send_alert: str when to send alert emails [none|nullroute|only|all attacks]
                *email_address: str email to send alerts to
                *profile_name: str type of profile to cover specific services  [Default|Webpage|Voice Chat|Video Chat|Minecraft|DNS Server|FPS]
                *profile_strength: str profile strength threshold [looser|loose|normal|tight|tighter]
                *udp_block: int option to out right block UDP to the server [0|1]
                *admin_ip: int option to treat the IP as an admin access IP [0|1]
        Returns:
            str json-encoded response
        """
        querystr = 'edit_Secureport=1'
        if secureport_id:
            querystr += "&secureportID=%s" % secureport_id
        else:
            if not data or "ip" not in data:
                raise Exception("IP Address must be specified for new secureport definitions.")

        return self._api_query(querystr, data)
