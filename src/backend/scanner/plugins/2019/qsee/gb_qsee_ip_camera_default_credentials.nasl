# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114101");
  script_version("2019-07-02T11:52:11+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:P");
  script_tag(name:"last_modification", value:"2019-07-02 11:52:11 +0000 (Tue, 02 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-05-31 13:32:20 +0200 (Fri, 31 May 2019)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Q-See IP Camera Default Credentials");
  script_dependencies("gb_qsee_ip_camera_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("qsee/ip_camera/detected");

  script_xref(name:"URL", value:"https://www.experts-exchange.com/questions/27985614/QSee-Security-System-Forgot-admin-password.html");

  script_tag(name:"summary", value:"The remote installation of Q-See's IP camera software is prone to
  a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration. The attacker would also be able to
  patch a custom firmware to further compromise the system.");

  script_tag(name:"insight", value:"The installation of Q-See's IP camera software is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to Q-See's IP camera software is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access or enable password protection.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

CPE = "cpe:/h:qsee:ip_camera";

if(!info = get_app_port_from_cpe_prefix(cpe: CPE, service: "www"))
  exit(0);

CPE = info["cpe"];
port = info["port"];

if(!get_app_location(cpe: CPE, port: port))
  exit(0);

#Credentials are in reversed order to allow for multiple passwords linked to the same user.
#The "anonymity" user was hardcoded into (or enabled on?) some hosts, found while testing.
creds = make_array("admin", "admin",
                   "123456", "admin");

url = "/RPC2_Login";

foreach cred(keys(creds)) {

  username = creds[cred];
  password = cred;

  #Remember to always increment the id before a new request linked to a session.
  id = 1;

  #1. Request parameters from the server
  data = '{"method":"global.login","params":{"userName":"' + username
  + '","password":"","clientType":"Web3.0","loginType":"Direct"},"id":' + id + '}';

  req = http_post_req(port: port, url: url, data: data);
  res = http_keepalive_send_recv(port: port, data: req);
  if(!res)
    continue;

  #2. Extract relevant information
  #Example:
  #{"error":{"code":268632079,"message":"Component error: login challenge!"},"id":1,"params":
  #{"authorization":"3339eaa9152eebff56a720c2f4dd0a62203a51dc","encryption":"Default",
  #"mac":"3CEF8C6101C0","random":"3734299","realm":"Login to 4C045ADPAG60CD"},"result":false,"session":1005027323}
  info = eregmatch(pattern: '"encryption"\\s*:\\s*"([^"]+)"(,"mac":"[^"]*")?,\\s*"random"\\s*:\\s*"([^"]+)",\\s*"realm"\\s*:\\s*"([^"]+)"\\s*},\\s*"result"\\s*:\\s*[^,]*,\\s*"session"\\s*:\\s*([^}]+)\\s*}', string: res, icase: TRUE);
  if(isnull(info[1]) || isnull(info[3]) || isnull(info[4]) || isnull(info[5]))
    continue;

  encryption = info[1];
  random = info[3];
  realm = info[4];
  sessionID = int(info[5]);

  #3. Classify this host based on the encryption type and calculate the hash accordingly
  if(encryption == "Basic") {
    pass = base64(str: username + ":" + password);
  } else if(encryption == "Default") {
    #This is their own form of "digest authentication"
    ha1 = toupper(hexstr(MD5(string(username, ":", realm, ":", password))));
    pass = toupper(hexstr(MD5(string(username, ":", random, ":", ha1))));
  } else {
    pass = password;
  }

  #4. Send the login form to the server
  #Example:
  #{"method":"global.login","params":{"userName":"admin","password":"D5CB53031D09A26D4175621AED5B7ED5",
  #"clientType":"Web3.0","loginType":"Direct","authorityType":"Default"},"id":2,"session":1005027323}
  data = '{"method":"global.login","params":{"userName":"' + username + '","password":"' + pass
  + '","clientType":"Web3.0","loginType":"Direct","authorityType":"' + encryption + '"},"id":' + ++id + ',"session":' + sessionID + '}';

  req = http_post_req(port: port, url: url, data: data);
  res = http_keepalive_send_recv(port: port, data: req);

  #Example of a successful login response(from one host where it was possible):
  #{ "id" : 10000, "params" : null, "result" : true, "session" : 462002603 }
  if(res && res =~ '"result"\\s*:\\s*true') {
    VULN = TRUE;
    if(!password)
      password = "<no/empty password>";
    report += '\n' + username + ':' + password;
  }
}

if(VULN) {
  report = 'It was possible to login with the following default credentials (username:password):\n' + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
