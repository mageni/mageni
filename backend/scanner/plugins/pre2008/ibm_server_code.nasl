###############################################################################
# OpenVAS Vulnerability Test
# $Id: ibm_server_code.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# IBM-HTTP-Server View Code
#
# Authors:
# Felix Huber <huberfelix@webtopia.de>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2001 Felix Huber
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

# v. 1.00 (last update 08.11.01)

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10799");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3518);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("IBM-HTTP-Server View Code");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 Felix Huber");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/ibm-http");

  script_tag(name:"summary", value:"IBM's HTTP Server on the AS/400 platform is vulnerable to an attack
  that will show the source code of the page -- such as an .html or .jsp
  page -- by attaching an '/' to the end of a URL.

  Example:
  http://www.example.com/getsource.jsp/");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

files = make_list(
"/index.html",
"/index.htm",
"/index.jsp",
"/default.html",
"/default.htm",
"/default.jsp",
"/home.html",
"/home.htm",
"/home.jsp" );

port = get_http_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

kb_files = http_get_kb_file_extensions( port:port, host:host, ext:"jsp" );
if( ! isnull( kb_files ) ) {
  files = make_list_unique( files, kb_files );
}

foreach file( files ) {
  url = file + "/";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );
  if( isnull( res ) ) continue;

  if( "Content-Type: www/unknown" >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );