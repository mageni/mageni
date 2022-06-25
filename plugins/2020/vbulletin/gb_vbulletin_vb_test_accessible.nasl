# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108827");
  script_version("2020-07-31T11:12:12+0000");
  script_tag(name:"last_modification", value:"2020-08-03 11:16:30 +0000 (Mon, 03 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-07-31 10:47:37 +0000 (Fri, 31 Jul 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("vBulletin 'vb_test.php' Information Disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_mandatory_keys("vbulletin/detected");

  script_tag(name:"summary", value:"The remote host is disclosing information if the vBulletin 'vb_test.php' script is exposed.");

  script_tag(name:"vuldetect", value:"Checks if the 'vb_test.php' script is exposed on the remote host.");

  script_tag(name:"impact", value:"An unauthenticated attacker might be able gather sensitive information about the
  remote vBulletin installation. Some versions of the script are also known to be vulnerable to a Cross-Site Scripting (XSS)
  vulnerability and a flaw related to the MySQL connection to the vBulletin database.");

  script_tag(name:"affected", value:"All vBulletin installations exposing the 'vb_test.php script.");

  script_tag(name:"solution", value:"Delete the script or restrict access to it.");

  script_xref(name:"URL", value:"https://www.golem.de/news/websicherheit-vbulletin-testskript-kann-dateien-leaken-2007-149629.html");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/vb_test.php";

if( http_vuln_check( port:port, url:url, pattern:"<title>vBulletin Test Script</title>", check_header:TRUE ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
