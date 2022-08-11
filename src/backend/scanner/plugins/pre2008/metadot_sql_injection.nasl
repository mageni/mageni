###############################################################################
# OpenVAS Vulnerability Test
# $Id: metadot_sql_injection.nasl 13226 2019-01-22 14:27:13Z cfischer $
#
# Multiple MetaDot Vulnerabilities
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

# From: JeiAr [security@gulftech.org]
# Subject: Multiple MetaDot Vulnerabilities [ All Versions ]
# Date: Friday 16/01/2004 03:11

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12024");
  script_version("$Revision: 13226 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-22 15:27:13 +0100 (Tue, 22 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9439);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Multiple MetaDot Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the latest version of Metadot.");

  script_tag(name:"summary", value:"The remote host is running Metadot, a popular open source portal software.

  Multiple vulnerabilities have been found in this product, which may allow a malicious user to inject arbitrary
  SQL commands, reveal valuable information about the server and perform Cross Site Scripting attacks.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = string(dir, "/metadot/index.pl?isa=Session&op=auto_login&new_user=&key='[foo]");
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( "DBAccess::sqlSelect('DBAccess', 'uid', 'session', 'sessionid=\'\'[foo]\'')" >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );