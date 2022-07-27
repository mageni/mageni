###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mybb_sid_sql_inj_vuln.nasl 12148 2018-10-29 09:52:06Z cfischer $
#
# MyBB sid Sql Injection Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:mybb:mybb';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903231");
  script_version("$Revision: 12148 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 10:52:06 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-02-26 11:23:07 +0530 (Wed, 26 Feb 2014)");
  script_name("MyBB sid Sql Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 SecPod");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("MyBB/installed");

  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/mybb-1612-sql-injection");
  script_xref(name:"URL", value:"http://mybb.com");

  script_tag(name:"summary", value:"This host is installed with MyBB and is prone to SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
  is possible to execute sql query.");

  script_tag(name:"insight", value:"Flaw is due to improper validation of user-supplied input passed to
  'sid' parameter in 'search.php' page.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code and gain sensitive information.");

  script_tag(name:"affected", value:"MyBB 1.6.12, previous versions may also be affected.");

  script_tag(name:"solution", value:"Upgrade to version 1.6.13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

url = dir + "/search.php?action=results&sid[0]=9afaea732cb32f06fa34b1888bd237e2&sortby=&order=";

if(http_vuln_check(port:port, url:url, check_header:FALSE, pattern:"expects parameter 2 to be string, array given", extra_check:"db_mysqli.php")) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
}

exit(0);