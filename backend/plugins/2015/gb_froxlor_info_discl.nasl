###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_froxlor_info_discl.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Froxlor Information Disclosure Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = 'cpe:/a:froxlor:froxlor';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106036");
  script_version("$Revision: 11872 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-08-03 13:44:55 +0700 (Mon, 03 Aug 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2015-5959");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Froxlor Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_froxlor_detect.nasl");
  script_mandatory_keys("froxlor/installed");

  script_tag(name:"summary", value:"Froxlor is prone to a information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted GET request and check the response.");

  script_tag(name:"insight", value:"An unauthenticated remote attacker is able to get the database
password via webaccess due to wrong file permissions of the /logs/ folder. The plain SQL password and
username may be stored in the /logs/sql-error.log file.");

  script_tag(name:"impact", value:"An unauthenticated remote attacker may be able to get the plain
SQL password and username or other sensitive information.");

  script_tag(name:"affected", value:"Froxlor version 0.9.33.1 and before.");

  script_tag(name:"solution", value:"Update to version 0.9.33.2 or later.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/07/29/8");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/logs/sql-error.log";
req = http_get(item: url, port: port);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

if (res =~ "HTTP/1.. 200 OK" && "SQLSTATE[HY000]" >< res) {
  report = report_vuln_url( port:port, url:url );
  security_message(port: port, data:report);
  exit(0);
}

exit(0);
