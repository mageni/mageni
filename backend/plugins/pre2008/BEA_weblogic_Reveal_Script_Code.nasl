###############################################################################
# OpenVAS Vulnerability Test
# $Id: BEA_weblogic_Reveal_Script_Code.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# BEA WebLogic Scripts Server scripts Source Disclosure
#
# Authors:
# Gregory Duchemin <plugin@intranode.com>
# Updated By: Antu Sanadi <santu@secpod> on 2010-07-06
# Updated CVSS Base
#
# Copyright:
# Copyright (C) 2001 INTRANODE
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
  script_oid("1.3.6.1.4.1.25623.1.0.10715");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2527);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("BEA WebLogic Scripts Server scripts Source Disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 INTRANODE");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.bea.com");

  script_tag(name:"solution", value:"Use the official patch available at the linked reference.");

  script_tag(name:"summary", value:"BEA WebLogic may be tricked into revealing the source code of JSP scripts
  by using simple URL encoding of characters in the filename extension.

  e.g.: default.js%70 (=default.jsp) won't be considered as a script but
  rather as a simple document.");

  script_tag(name:"affected", value:"Vulnerable systems: WebLogic version 5.1.0 SP 6

  Immune systems: WebLogic version 5.1.0 SP 8");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

signature = "<%="; #signature of Jsp.

port = get_http_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string( dir, "/index.js%70" );

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( signature >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

files = http_get_kb_file_extensions( port:port, host:host, ext:"jsp" );
if( isnull( files ) ) exit( 0 );

files = make_list( files );
file = ereg_replace( string:files[0], pattern:"(.*js)p$", replace:"\1" );

url = string( file, "%70" );

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( signature >< res ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
