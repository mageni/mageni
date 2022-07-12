###############################################################################
# OpenVAS Vulnerability Test
# $Id: odbc_tools_check.nasl 11998 2018-10-20 18:17:12Z cfischer $
#
# ODBC tools check
#
# Authors:
# David Kyger <david_kyger@symantec.com>
#
# Copyright:
# Copyright (C) 2002 David Kyger
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
  script_oid("1.3.6.1.4.1.25623.1.0.11872");
  script_version("$Revision: 11998 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 20:17:12 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("ODBC tools check");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 David Kyger");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Remove the specified ODBC tools from the /scripts/tools directory.");

  script_tag(name:"summary", value:"Many Web servers ship with default CGI scripts which allow for ODBC access
  and configuration. Some of these test ODBC tools are present on the remote web server");

  script_tag(name:"impact", value:"ODBC tools could allow a malicious user to hijack and redirect ODBC traffic,
  obtain SQL user names and passwords or write files to the local drive of a vulnerable server.

  Example: /scripts/tools/getdrvrs.exe");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

vuln = FALSE;
report = "The following ODBC tools were found on the server:";

port = get_http_port(default:80);

foreach url( make_list( "/scripts/tools/getdrvrs.exe", "/scripts/tools/dsnform.exe" ) ) {
  if( is_cgi_installed_ka( item:url, port:port ) ) {
    report += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE );
    vuln = TRUE;
  }
}

if( vuln ) {
  security_message( port:port, data:report );
}

exit( 0 );