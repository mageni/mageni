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
  script_oid("1.3.6.1.4.1.25623.1.0.114094");
  script_version("2019-05-03T12:45:16+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 12:45:16 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2019-04-30 13:25:57 +0200 (Tue, 30 Apr 2019)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Oncam IP 360 Default Credentials");
  script_dependencies("gb_oncam_ip360_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("oncam/ip360/detected");

  script_xref(name:"URL", value:"https://www.oncamgrandeye.com/wp-content/uploads/2017/11/evo-05_mini_recessed_camera_quick_start_guide.pdf");

  script_tag(name:"summary", value:"The remote installation of Oncam IP 360 is prone to
  a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Oncam IP 360 is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to Oncam IP 360 is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

CPE = "cpe:/a:oncam:ip360";

if(!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if(!get_app_location(cpe: CPE, port: port)) # nb: Unused but added to have a reference to the Detection-NVT in the GSA
  exit(0);

#Credential is in reversed order to allow for multiple passwords linked to the same user.
creds = make_array("admin", "admin");

#The MAC address can only be obtained by somebody that is logged in.
url = "/admin/getparam.cgi?macaddress";

foreach cred(keys(creds)) {

  username = creds[cred];
  password = cred;

  auth = "Basic " + base64(str: username + ":" + password);

  req = http_get_req(port: port, url: url, add_headers: make_array("Authorization", auth));

  res = http_keepalive_send_recv(port: port, data: req);

  #Example -> macaddress=00:12:35:01:0B:16
  if(res =~ "macaddress=[0-9a-fA-F:]+") {
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
