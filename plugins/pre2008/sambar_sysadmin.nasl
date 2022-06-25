###############################################################################
# OpenVAS Vulnerability Test
# $Id: sambar_sysadmin.nasl 5134 2017-01-30 08:20:15Z cfi $
#
# Sambar /sysadmin directory 2
#
# Authors:
# Hendrik Scholz <hendrik@scholz.net>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
# Changes by rd : use ereg() instead of ><
#
# Copyright:
# Copyright (C) 2000 Hendrik Scholz
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10416");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2255);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Sambar /sysadmin directory 2");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 Hendrik Scholz");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 3135);
  script_mandatory_keys("www/sambar");

  script_tag(name:"solution", value:"Change the passwords via the webinterface or use a real webserver
  like Apache.");

  script_tag(name:"summary", value:"The Sambar webserver is running.

  It provides a web interface for configuration purposes.

  The admin user has no password and there are some other default users without
  passwords. Everyone could set the HTTP-Root to c:\ and delete existing files!

  *** This may be a false positive - go to http://example.com/sysadmin/ and
  have a look at it by yourself.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:3135 );

url = "/sysadmin/dbms/dbms.htm";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

if( egrep( pattern:"[sS]ambar", string:res ) ) {
  if( ereg( pattern:"^HTTP/[0-9]\.[0-9] 403 ", string:res ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report);
    exit( 0 );
  }
}

exit( 99 );