###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dahua_devices_default_credentials.nasl 12426 2018-11-19 17:35:36Z tpassfeld $
#
# Dahua Devices Default Credentials
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114040");
  script_version("$Revision: 12426 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 18:35:36 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-15 21:06:41 +0200 (Mon, 15 Oct 2018)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Dahua Devices Default Credentials");
  script_dependencies("gb_dahua_devices_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dahua/device/detected");

  script_xref(name:"URL", value:"https://customvideosecurity.com/blog/tag/default-password-axis/");

  script_tag(name:"summary", value:"The remote installation of Dahua's ip camera software (or a derivative of such)
  is prone to a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Dahua's ip camera software (or a derivative of such)  is
  lacking a proper password configuration, which makes critical information and actions accessible for people with
  knowledge of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to Dahua's ip camera software is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

CPE = "cpe:/a:dahua:nvr";

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!get_app_location(cpe: CPE, port: port)) exit(0); # nb: Unused but added to have a reference to the Detection-NVT in the GSA

#There is an artificial password limit of 6 characters for some reason.
#Credentials for: 1. Dahua; 2. Lorex
#Because we can't use multiple keys, the first part(key) is the password and the second part(value) is the username.
creds = make_array("admin", "admin",
                   "000000", "admin");

url = "/RPC2_Login";

foreach cred(keys(creds)) {

  #To avoid confusion with previous scripts, because of the reversed order:
  username = creds[cred];
  password = cred;

  #Initial POST-request to acquire sessionID
  id = "1" + rand_str(length:4, charset:"1234567890");
  data = '{"method":"global.login","params":{"userName":"' + username + '","password":"","clientType":"Dahua3.0-Web3.0"},"id":' + id + '}';

  req = http_post_req(port: port,
                      url: url,
                      data: data,
                      add_headers: make_array("X-Request", "JSON",
                                              "Accept", "text/javascript, text/html, application/xml, text/xml, */*"));

  res = http_keepalive_send_recv(port: port, data: req);

  #"session" : 51048704 }
  sess = eregmatch(pattern: '"session"\\s*:\\s*([0-9]+)\\s*\\}', string: res);
  if(!isnull(sess[1])) sessionID = sess[1];
  else continue;

  #"encryption" : "OldDigest"
  encryp = eregmatch(pattern: '"encryption"\\s*:\\s*"([a-zA-Z]+)"', string: res);
  if(!isnull(encryp[1])) encryptionType = encryp[1];
  else encryptionType = "";

  #"random" : ""
  random = eregmatch(pattern: '"random"\\s*:\\s*"([^"]+)"', string: res);
  if(!isnull(random[1])) random_string = random[1];
  else if(encryptionType == "Default") break; #Because "default" requires this value and the encryptionType is set globally by the server.

  #"realm":"Login to 3EPAZ6EF4C8FN59"
  rea = eregmatch(pattern: '"realm"\\s*:\\s*"([^"]+)"', string: res);
  if(!isnull(rea[1])) realm = rea[1];
  else realm = "";

  #According to function "get_Auth" in file /js/index.js:
  if(encryptionType == "Basic") {
    pass = base64(str: username + ":" + password);
  }
  else if(encryptionType == "Default") {
    HA1 = hexstr(MD5(string(username, ":", realm, ":", password)));
    pass = hexstr(MD5(string(username, ":", random_string, ":", HA1)));
  }
  else if(encryptionType == "OldDigest") {
    #case "OldDigest": return (new RPCLogin).webEncryption(password);
    #and then in function webEncryption -> a = g_ocx.ProtocolPluginWithWebCall(JSON.encode({ and so on.
    #this is probably calling a function to decrypt passwords in the webplugin.exe that you need
    #to install before you can login. There is no obvious way to obtain that function's source code directly.
    #Thus, you would need to decompile or disassemble the .exe file to acquire further information.

    #Temporary solution for "admin" "admin" (the hash seems to always be the same, but it is very short)
    if(password == "admin") pass = "6QNMIQGe";
    else break;
  }
  else {
    pass = password;
  }

  data = '{"method":"global.login","session":' + sessionID + ',"params":{"userName":"' + username + '","password":"' + pass + '","clientType":"Dahua3.0-Web3.0", "authorityType":"' + encryptionType + '"},"id":' + id + '}';

  req = http_post_req(port: port, url: url, data: data, add_headers: make_array("X-Request", "JSON",
                                                                                "X-Requested-With", "XMLHttpRequest",
                                                                                "Dhwebclientsessionid", sessionID,
                                                                                "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8",
                                                                                "Accept", "text/javascript, text/html, application/xml, text/xml, */*"));

  res = http_keepalive_send_recv(port: port, data: req);

  #{ "id" : 10000, "params" : null, "result" : true, "session" : 52955133 }
  if(res =~ '"result"\\s*:\\s*true' && res =~ '"params"\\s*:\\s*null') {
    VULN = TRUE;
    report += '\nusername: "' + username + '", password: "' + password + '"';
  }
}

if(VULN) {
  report = "It was possible to login with the following default credentials: " + report;
  security_message(port: port, data: report);
  exit(0);
}
exit(99);
