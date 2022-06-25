###############################################################################
# OpenVAS Vulnerability Test
# $Id: counter.nasl 13210 2019-01-22 09:14:04Z cfischer $
#
# counter.exe vulnerability
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2003 John Lampe
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
  script_oid("1.3.6.1.4.1.25623.1.0.11725");
  script_version("$Revision: 13210 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-22 10:14:04 +0100 (Tue, 22 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(267);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-1999-1030");
  script_name("counter.exe vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2003 John Lampe");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Remove it from the cgi-bin or scripts directory.");

  script_tag(name:"summary", value:"The CGI 'counter.exe' exists on this webserver.
  Some versions of this file are vulnerable to remote exploit.");

  script_tag(name:"impact", value:"An attacker may make use of this file to gain access to
  confidential data or escalate their privileges on the Web server.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/counter.exe";

  if( is_cgi_installed_ka( item:url, port:port ) ) {

    req = string( "GET ", dir, "/counter.exe?%0A", "\r\n\r\n" );
    soc = open_sock_tcp( port );
    if( soc ) {
      send( socket:soc, data:req );
      r = http_recv( socket:soc );
      close( soc );
    } else {
      exit( 0 );
    }

    soc2 = open_sock_tcp( port );
    if( ! soc2 ) {
      security_message( port:port );
      exit( 0 );
    }

    send( socket:soc2, data:req );
    r = http_recv( socket:soc2 );
    if( ! r ) {
      security_message( port:port );
      exit( 0 );
    }

    if( egrep( pattern:".*Access Violation.*", string:r ) ) {
      security_message( port:port );
      exit( 0 );
    }
  }
}

exit( 99 );