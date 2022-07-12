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
  script_oid("1.3.6.1.4.1.25623.1.0.114087");
  script_version("2019-04-04T14:50:45+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"2019-04-04 14:50:45 +0000 (Thu, 04 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-03-20 14:57:35 +0100 (Wed, 20 Mar 2019)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Intellio Visus Default Credentials");
  script_dependencies("gb_intellio_visus_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("intellio/visus/detected");

  script_xref(name:"URL", value:"https://technodocbox.com/Cameras_and_Camcorders/67505238-Firmware-version-3-2-0.html");

  script_tag(name:"summary", value:"The remote installation of Intellio Visus is prone to
  a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Intellio Visus is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to Intellio Visus' web interface is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

CPE = "cpe:/a:intellio:visus";

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!get_app_location(cpe: CPE, port: port)) exit(0); # nb: Unused but added to have a reference to the Detection-NVT

creds = make_array("admin", "admin");

#Classify the type of authentication method that is being used
url = "/login";

req = http_get_req(port: port, url: url);

res = http_keepalive_send_recv(port: port, data: req);

if('"BadRequestException"' >< res)
  hostType = "POST_login";
else
  hostType = "GET_authorize";

foreach cred(keys(creds)) {

  if(hostType == "GET_authorize") {
    #Example:
    #/authorize?user=admin&password=admin
    url = "/authorize?user=" + cred + "&password=" + creds[cred];

    req = http_get_req(port: port, url: url);

  } else if(hostType == "POST_login") {
    #URL is still "/login" from above

    #Example:
    #{"User":"admin","Password":"admin"}
    data = '{"User":"' + cred + '","Password":"' + creds[cred] + '"}';

    auth = "user=" + cred + "; password=" + creds[cred];

    req = http_post_req(port: port, url: url, data: data, add_headers: make_array("Cookie", auth));
  }

  res = http_keepalive_send_recv(port: port, data: req);

  #Example response for hostType "GET_authorize":
  #- Set-Cookie: session=a8f6745c4882403fa61bbca679805005; http-only
  #- Set-Cookie: user=admin

  #Example response for hostType "POST_login":
  #"Type" : "Response",
  #         "Data" : {
  #           "sid" : "b7794a52"
  #         }
  if((res =~ "Set-Cookie:\s*session=" && res =~ "Set-Cookie:\s*user=")
    || res =~ '"sid"\\s*:\\s*"[^"]+"') {
    VULN = TRUE;
    report += '\n' + cred + ':' + creds[cred];
  }
}

if(VULN) {
  report = 'It was possible to login with the following default credentials (username:password):\n' + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
