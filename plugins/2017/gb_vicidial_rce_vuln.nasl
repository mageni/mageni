##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vicidial_rce_vuln.nasl 11901 2018-10-15 08:47:18Z mmartin $
#
# VICIDIAL RCE Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:vicidial:vicidial";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106838");
  script_version("$Revision: 11901 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-15 10:47:18 +0200 (Mon, 15 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-30 10:12:02 +0700 (Tue, 30 May 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VICIDIAL RCE Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_vicidial_detect.nasl");
  script_mandatory_keys("vicidial/installed");

  script_tag(name:"summary", value:"VICIDIAL Contact Center Suite is prone to a remote OS command execution
vulnerability.");

  script_tag(name:"insight", value:"VICIdial versions 2.9 RC1 to 2.13 RC1 allows unauthenticated users to
execute arbitrary operating system commands as the web server user if password encryption is enabled (disabled
by default).");

  script_tag(name:"impact", value:"An unauthenticated attacker may execute arbitrary OS commands as the web
server.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP request and checks if input filtering is not patched
and if password encryption is supported which indicates that the server is vulnerable.");

  script_tag(name:"solution", value:"See the referenced link for a solution.");

  script_xref(name:"URL", value:"http://www.vicidial.org/VICIDIALmantis/view.php?id=1016");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

user = rand_str(length: 10, charset: "ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz");
pass = '#' + rand_str(length: 10, charset: "ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz") + '&#';
userpass = user + ':' + pass;
userpass64 = base64(str: userpass);
authstr = "Basic " + userpass64;

req = http_get_req(port: port, url: dir + "/vicidial_sales_viewer.php",
                   add_headers: make_array("Authorization", authstr));
res = http_keepalive_send_recv(port: port, data: req);

if (!eregmatch(pattern: "\|" + user + "\|" + pass + "\|BAD\|", string: res))
  exit(99);

if (http_vuln_check(port: port, url: "/agc/bp.pl", pattern: "Bcrypt password hashing script",
                    check_header: TRUE)) {
  report = "Result of the check:\nInput filtering is not patched and password encryption is supported. Which
indicates that the server is vulnerable if password encryption is enabled.";
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
