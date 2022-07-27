###############################################################################
# OpenVAS Vulnerability Test
# $Id: consolehelp.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# WebLogic source code disclosure
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
# Modifications by Tenable Network Security :
# -> Check for an existing .jsp file, instead of /default.jsp
# -> Expect a jsp signature
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11724");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1518);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2000-0682");
  script_name("WebLogic source code disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 John Lampe");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA02-03.jsp");

  script_tag(name:"solution", value:"The vendor has released updates. See the linked advisory for more information.");

  script_tag(name:"summary", value:"There is a bug in the Weblogic web application. Namely,
  by inserting a /ConsoleHelp/ into a URL, critical source code files may be viewed.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

jspfiles = http_get_kb_file_extensions( port:port, host:host, ext:"jsp" );

if( isnull( jspfiles ) )
  jspfiles = make_list( "default.jsp" );
else
  jspfiles = make_list( jspfiles );

cnt = 0;

foreach file( jspfiles ) {
  url = "/ConsoleHelp/" + file;
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );
  if( "<%" >< res && "%>" >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
  cnt++;
  if( cnt > 10 )
    exit( 0 );
}

exit( 99 );