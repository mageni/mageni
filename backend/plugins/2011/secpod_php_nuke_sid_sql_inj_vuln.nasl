###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_nuke_sid_sql_inj_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# PHP-Nuke 'sid' Parameter SQL Injection Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:phpnuke:php-nuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902612");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP-Nuke 'sid' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_php_nuke_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php-nuke/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to add, modify or
  delete data in the back end database.");
  script_tag(name:"affected", value:"PHP-Nuke versions 5.6, 6.0, 6.5 RC1, 6.5 RC2, 6.5 RC3, 6.5");
  script_tag(name:"insight", value:"The flaw is caused by input validation errors in the 'article.php'
  when processing user-supplied data in 'sid' parameter, which could be exploited
  by attackers to execute SQL code.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running PHP-Nuke and is prone to SQL injection
  vulnerability.");

  script_xref(name:"URL", value:"http://www.1337day.com/exploits/16550");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/11599");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/vulnwatch/2003-q1/0147.html");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

url = dir + "/article.php?sid=sid=24%27";
req = http_get( item:url, port:port);
res = http_keepalive_send_recv( port:port, data:req );

if( "mysql_fetch_row()" >< res && "MySQL result" >< res ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );