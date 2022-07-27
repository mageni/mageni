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
  script_oid("1.3.6.1.4.1.25623.1.0.114066");
  script_version("$Revision: 13498 $");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:08:46 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-05 15:30:18 +0100 (Tue, 05 Feb 2019)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Samsung iPolis Default Credentials");
  script_dependencies("gb_samsung_ipolis_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("samsung/ipolis/detected");

  script_xref(name:"URL", value:"https://www.a1securitycameras.com/technical-support/default-username-passwords-ip-addresses-for-surveillance-cameras/");

  script_tag(name:"summary", value:"The remote installation of Samsung iPolis is prone to
  a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Samsung iPolis is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to Samsung iPolis is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

CPE = "cpe:/a:samsung:ipolis";

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!get_app_location(cpe: CPE, port: port)) exit(0); # nb: Unused but added to have a reference to the Detection-NVT

creds = make_array("admin", "4321");

url = "/home/monitoring.cgi";

foreach cred(keys(creds)) {

  req = http_get_req(port: port, url: url, add_headers: make_array("Accept-Encoding", "gzip, deflate",
                                                                   "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"));

  res = http_keepalive_send_recv(port: port, data: req);

  #WWW-Authenticate: Digest realm="iPolis", nonce="88b833d46115b6c94957bd925b7cb1bc", qop="auth"
  info = eregmatch(pattern: 'Digest realm="([^"]+)", nonce="([0-9a-zA-Z]+)",', string: res);
  if(isnull(info[1]) || isnull(info[2])) continue;
  realm = info[1];
  nonce = info[2];

  #Digest authentication according to the standard showcased here: https://code-maze.com/http-series-part-4/#digestauth
  cnonce = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789", length:16);
  qop = "auth";
  nc = "00000001";
  ha1 = hexstr(MD5(string(cred, ":", realm, ":", creds[cred])));
  ha2 = hexstr(MD5(string("GET:", url)));
  response = hexstr(MD5(string(ha1, ":", nonce, ":", nc, ":", cnonce, ":", qop, ":", ha2)));

  auth = 'Digest username="' + cred + '", realm="' + realm + '", nonce="' + nonce + '", uri="' + url + '", response="' + response + '", qop=' + qop + ', nc=' + nc + ', cnonce="' + cnonce + '"';

  req = http_get_req(port: port, url: url, add_headers: make_array("Accept-Encoding", "gzip, deflate",
                                                                   "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                                                   "Authorization", auth));
  res = http_keepalive_send_recv(port: port, data: req);

  if("var model" >< res && "var devicePort" >< res) {
    VULN = TRUE;
    report += '\nusername: "' + cred + '", password: "' + creds[cred] + '"';
  }

}

if(VULN) {
  report = "It was possible to login with the following default credentials: " + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
