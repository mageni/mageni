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
  script_oid("1.3.6.1.4.1.25623.1.0.114103");
  script_version("2019-07-02T02:13:59+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-07-02 02:13:59 +0000 (Tue, 02 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-02 02:10:57 +0000 (Tue, 02 Jul 2019)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Default Accounts");

  script_name("Reolink IP Cameras Default Credentials");

  script_dependencies("gb_reolink_ip_cameras_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("reolink/ip_camera/detected");

  script_xref(name:"URL", value:"https://support.reolink.com/hc/en-us/articles/360003516613-How-to-Reset-Bullet-or-Dome-Cameras");

  script_tag(name:"summary", value:"The remote installation of Reolink's IP camera software is prone to
  a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Reolink's IP camera software is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to Reolink's IP camera software is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access or enable password protection.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

CPE = "cpe:/h:reolink:ip_camera";

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port))
  exit(0);

creds = make_array("", "admin",
                   "admin", "admin");
url = "/cgi-bin/api.cgi?cmd=login&token=null";

foreach cred (keys(creds)) {

  username = creds[cred];
  password = cred;

  #[{"cmd":"Login","action":0,"param":{"User":{"userName":"admin","password":""}}}]
  data = '[{"cmd":"Login","action":0,"param":{"User":{"userName":"' + username + '","password":"' + password + '"}}}]';

  req = http_post_req(port: port, url: url, data: data);
  res = http_keepalive_send_recv(port: port, data: req);

  #"leaseTime" : 3600,
  #"name" : "685b98ed6b37e22"
  if (res =~ '"leaseTime"\\s*:\\s*[0-9]+,' && res =~ '"name"\\s*:\\s*"[0-9a-zA-Z]+"') {
    VULN = TRUE;
    if (!password)
      password = "<no/empty password>";
    report += '\n' + username + ':' + password;
  }
}

if (VULN) {
  report = 'It was possible to login with the following default credentials (username:password):\n' + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
