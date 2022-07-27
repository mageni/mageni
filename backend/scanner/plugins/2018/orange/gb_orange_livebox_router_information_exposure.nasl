###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orange_livebox_router_information_exposure.nasl 12938 2019-01-04 07:18:11Z asteins $
#
# Orange Livebox Router Information Exposure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.114055");
  script_version("$Revision: 12938 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-01-04 08:18:11 +0100 (Fri, 04 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-12-27 18:03:44 +0100 (Thu, 27 Dec 2018)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_name("Orange Livebox Router Information Exposure");
  script_dependencies("gb_orange_livebox_router_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("orange/livebox/detected");

  script_xref(name:"URL", value:"https://badpackets.net/over-19000-orange-livebox-adsl-modems-are-leaking-their-wifi-credentials/");

  script_cve_id("CVE-2018-20377");

  script_tag(name:"summary", value:"The remote installation of Orange Livebox is prone to
  an information exposure vulnerability. The webserver leaks the WiFi security protocol, SSID, and password in plain text.");

  script_tag(name:"impact", value:"This vulnerability might be exploited to obtain login information, if the leaked password
  matches the one used to log in as an administrator. Furthermore, people exploiting this vulnerability locally could obtain
  authenticated access to the WiFi access point.");

  script_tag(name:"insight", value:"This vulnerability affects all firmware versions before 00.96.00.96.613E.");

  script_tag(name:"vuldetect", value:"Sends a specific HTTP GET request to the host and checks if the information is being leaked.");

  script_tag(name:"solution", value:"Update to firmware version 00.96.00.96.613E or later. Also make sure the WiFi password never
  matches the password of the administrator in case this ever happens again.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");


CPE = "cpe:/h:orange:livebox";

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!get_app_location(cpe: CPE, port: port)) exit(0); # nb: Unused but added to have a reference to the Detection-NVT in the GSA

url = "/get_getnetworkconf.cgi";

req = http_get_req(port: port, url: url);

res = http_send_recv(port: port, data: req);

if(res =~ "<html>\s*<body>\s*Orange-[0-9a-zA-Z_]+<BR>\s*[0-9a-zA-Z_]+<BR>") {
  report = "It was possible to obtain the SSID and the WiFi password.";
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
