###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_basler_ip_camera_default_credentials.nasl 11328 2018-09-11 12:32:47Z tpassfeld $
#
# Basler IP Camera Default Credentials
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
  script_oid("1.3.6.1.4.1.25623.1.0.114030");
  script_version("$Revision: 11328 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 14:32:47 +0200 (Tue, 11 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-10 12:59:11 +0200 (Mon, 10 Sep 2018)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Basler IP Camera Default Credentials");
  script_dependencies("gb_basler_ip_camera_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("basler/ip_camera/detected");

  script_xref(name:"URL", value:"https://ipvm.com/reports/ip-cameras-default-passwords-directory");

  script_tag(name:"summary", value:"The remote Basler IP Camera is prone to
  a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Basler IP Camera is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to Basler IP Camera is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

CPE = "cpe:/a:basler:ip_camera";

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!get_app_location(cpe: CPE, port: port)) exit(0); # nb: Unused but added to have a reference to the Detection-NVT

username = "admin";
password = "admin";

url = "/cgi-bin/auth_if.cgi?Login";

data = "Auth.Username=" + username + "&Auth.Password=" + password;

req = http_post_req(port: port,
                    url: url,
                    data: data,
                    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));

res = http_keepalive_send_recv(port: port, data: req);

if("success: true" >< res && "errorcode: 0" >< res) {
  report = 'It was possible to login via the default username "' + username + '" and the default password "' + password + '".';

  security_message(port: port, data: report);
  exit(0);
}

exit(99);
