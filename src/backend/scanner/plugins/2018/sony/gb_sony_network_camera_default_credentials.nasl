###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sony_network_camera_default_credentials.nasl 11356 2018-09-12 10:46:43Z tpassfeld $
#
# Sony Network Camera Default Credentials
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.114023");
  script_version("$Revision: 11356 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 12:46:43 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-08-21 16:35:01 +0200 (Tue, 21 Aug 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Sony Network Camera Default Credentials");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_sony_network_camera_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sony/network_camera/detected");

  script_tag(name:"summary", value:"Sony network cameras use the default credentials admin:admin.");
  script_tag(name:"vuldetect", value:"Tries to login using default credentials.");
  script_tag(name:"affected", value:"All Sony SNC cameras using this web interface.");
  script_tag(name:"solution", value:"Change the default password.");

  script_xref(name:"URL", value:"https://ipvm.com/reports/ip-cameras-default-passwords-directory");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

CPE = "cpe:/h:sony:network_camera";

if(!port = get_app_port(cpe: CPE)) exit(0);

username = "admin";
password = "admin";

auth_header = make_array("Authorization", "Basic " + base64(str: username + ":" + password));
req = http_get_req(port: port, url: "/command/inquiry.cgi?inqjs=network", add_headers: auth_header);
res = http_keepalive_send_recv(port: port, data: req);

if("Dhcp=" >< res || "DnsAuto=" >< res || "Ip=" >< res || "Subnetmask=" >< res || "Gateway=" >< res) {
  report = 'It was possible to login using the username "' + username + '" and the password "' + password + '".';
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
