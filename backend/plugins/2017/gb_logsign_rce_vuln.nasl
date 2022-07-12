###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_logsign_rce_vuln.nasl 11324 2018-09-11 10:42:18Z asteins $
#
# Logsign Remote Command Execution Vulnerability
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

CPE = "cpe:/a:logsign:logsign";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106651");
  script_version("$Revision: 11324 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 12:42:18 +0200 (Tue, 11 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-03-14 12:58:36 +0700 (Tue, 14 Mar 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Logsign Remote Command Execution Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_logsign_detect.nasl");
  script_mandatory_keys("logsign/installed");

  script_tag(name:"summary", value:"Logsign is prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP request and checks the response.");

  script_tag(name:"insight", value:"Logsign has a publicly accessible endpoint. That endpoint takes a user input
and then use it during operating system command execution without proper validation.");

  script_tag(name:"solution", value:"Logsign provides a patch to solve this vulnerability.");

  script_xref(name:"URL", value:"https://pentest.blog/unexpected-journey-3-visiting-another-siem-and-uncovering-pre-auth-privileged-remote-code-execution/");

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

if (dir == "/")
  dir = "";

url = dir + "/api/log_browser/validate";

rand = rand_str(length: 15, charset: "ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz");
data = '{"file":"'+ rand + '.raw"}';

req = http_post_req(port: port, url: url, data: data, add_headers: make_array("Content-Type", "application/json"));
res = http_keepalive_send_recv(port: port, data: req);

if ('{"message": "success", "success": true}' >< res) {
  security_message(port: port);
  exit(0);
}

exit(0);
