###############################################################################
# OpenVAS Vulnerability Test
# $Id: cgicso_command_execution.nasl 12008 2018-10-22 08:12:11Z cfischer $
#
# CGIEmail's CGICso (Send CSO via CGI) Command Execution Vulnerability
#
# Authors:
# Noam Rathaus
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID,  deleted link as it is provided in Bugtraq exploits section
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus
# Copyright (C) 2001 SecurITeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10779");
  script_version("$Revision: 12008 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 10:12:11 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-1652");
  script_bugtraq_id(6141);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CGIEmail's CGICso (Send CSO via CGI) Command Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2001 SecurITeam");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"The server can be compromised by executing commands as the web server's
  running user (usually 'nobody').");

  script_tag(name:"solution", value:"Modify cgicso.h to contain a strict setting of your finger host.

  Example:

  Define the following in cgicso.h:

  #define CGI_CSO_HARDCODE

  #define CGI_CSO_FINGERHOST 'localhost'");

  script_tag(name:"summary", value:"The remote host seems to be vulnerable to a security problem in
  CGIEmail (cgicso).  The vulnerability is caused by inadequate processing of queries by CGIEmail's
  cgicso and results in a command execution vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir +  "/cgicso?query=AAA";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req );

  if( "400 Required field missing: fingerhost" >< buf ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );
