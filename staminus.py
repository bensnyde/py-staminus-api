import requests
import requests.auth


class Staminus:
    def __init__(self, client_id, client_secret, redirect_uri, username, password):
        self.USERNAME = username
        self.TOKEN = self.get_auth_token(client_id, client_secret, redirect_uri, password)

        if not self.TOKEN:
            return None


    def get_auth_token(self, client_id, client_secret, redirect_uri, password):
        try:
            client_auth = requests.auth.HTTPBasicAuth(client_id, client_secret)
            post_data = {
                "redirect_uri": redirect_uri,
                'username': self.USERNAME, 
                'grant_type': 'password', 
                'password': password
            }

            response = requests.post("https://api.staminus.net/token.php", auth=client_auth, data=post_data)

            return response.json()['access_token']
        except Exception as ex:
            print "Failed to retrieve Access Token: %s" % ex
            return False


    def api_query(self, script):
        try:
            response = requests.post("https://api.staminus.net/?%s&accountID=%s&access_token=%s" % (script, self.USERNAME, self.TOKEN))
            return response.json()
        except Exception as ex:
            print "API Query failed: %s" % ex
            return False


    def get_servers(self):
        return self.api_query('servers=1')


    def get_attack_logs(self, server_id):
        return self.api_query('ddos_report=1&serverID=%s' % server_id)


    def get_secure_ports(self):
        return self.api_query('get_all_Secureports=1')


    def get_secure_port(self, secureport_id):
        return self.api_query('secureport_blocks=1&secureIP=%s' % secureport_id)


    def clear_secure_ports(self, secureport_id):
        return self.api_query('secureport_blocks_clear=1&secureIP=%s' % secureport_id)


    def clear_secure_port(self, secureport_id, block_id):
        return self.api_query('secureport_blocks_clear_specific=1&secureIP=%s&blockID=%s' % (secureport_id, block_id))
