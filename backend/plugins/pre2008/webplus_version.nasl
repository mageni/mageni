###############################################################################
# OpenVAS Vulnerability Test
# $Id: webplus_version.nasl 12001 2018-10-21 11:10:33Z cfischer $
#
# TalentSoft Web+ version detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Changes by rd :
#  - use of function to simplify code
#
# Copyright:
# Copyright (C) 2000 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10373");
  script_version("$Revision: 12001 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-21 13:10:33 +0200 (Sun, 21 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_name("TalentSoft Web+ version detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 SecuriTeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"affected", value:"This bug is known to exist in Web+ 4.X as of March 1999, and probably exists
  in all previous versions as well.");

  script_tag(name:"summary", value:"This plug-in detects the version of Web+ CGI. The Web+ CGI has a known
  vulnerability that enables a remote attacker to gain access to local files.

  This test in itself does not verify the vulnerability but rather tries to
  discover the version of Web+ which is installed.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

function extract_version( result, port ) {

  resultrecv = strstr(result, "Version: </b>: ");
  resultsub = strstr(resultrecv, string("\n"));
  resultrecv = resultrecv - resultsub;
  resultrecv = resultrecv - "</b>";

  banner = banner + resultrecv;
  banner = banner + string("\n");

  resultrecv = strstr(result, "<br><b>Web+ Server Compile Number</b>: ");
  resultsub = strstr(resultrecv, string("\n"));
  resultrecv = resultrecv - resultsub;
  resultrecv = resultrecv - "<br>";
  resultrecv = resultrecv - "<b>";
  resultrecv = resultrecv - "</b>";

  banner = banner + resultrecv;
  banner = banner + string("\n");

  resultrecv = strstr(result, "<br><b>Web+ Client Compile Number</b>: ");
  resultsub = strstr(resultrecv, string("\n"));
  resultrecv = resultrecv - resultsub;
  resultrecv = resultrecv - "<br>";
  resultrecv = resultrecv - "<b>";
  resultrecv = resultrecv - "</b>";

  banner = banner + resultrecv;
  banner = banner + string("\n");

  resultrecv = strstr(result, "<br><b>Operating System</b>: ");
  resultsub = strstr(resultrecv, string("\n"));
  resultrecv = resultrecv - resultsub;
  resultrecv = resultrecv - "<br>";
  resultrecv = resultrecv - "<b>";
  resultrecv = resultrecv - "</b>";

  banner = banner + resultrecv;
  banner = banner + string("\n");

  resultrecv = strstr(result, "Web+ Server Version");
  resultsub = strstr(resultrecv, string("\n"));
  resultrecv = resultrecv - resultsub;
  resultrecv = resultrecv - "<B>";
  resultrecv = resultrecv - "</B>";

  banner = banner + resultrecv;
  banner = banner + string("\n");

  resultrecv = strstr(result, "Web+ Monitor Server Version");
  resultsub = strstr(resultrecv, string("\n"));
  resultrecv = resultrecv - resultsub;
  resultrecv = resultrecv - "<B>";
  resultrecv = resultrecv - "</B>";

  banner = banner + resultrecv;
  banner = banner + string("\n");

  resultrecv = strstr(result, "Web+ Client Version");
  resultsub = strstr(resultrecv, string("\n"));
  resultrecv = resultrecv - resultsub;
  resultrecv = resultrecv - "<B>";
  resultrecv = resultrecv - "</B>";

  banner = banner + resultrecv;
  banner = banner + string("\n");

  resultrecv = strstr(result, "Release Date");
  resultsub = strstr(resultrecv, string("\n"));
  resultrecv = resultrecv - resultsub;
  resultrecv = resultrecv - "<B>";
  resultrecv = resultrecv - "</B>";

  banner = banner + resultrecv;
  banner = banner + string("\n");

  resultrecv = strstr(result, "User Name");
  resultsub = strstr(resultrecv, string("\n"));
  resultrecv = resultrecv - resultsub;
  resultrecv = resultrecv - "<B>";
  resultrecv = resultrecv - "</B>";
  resultrecv = resultrecv - "<i>";
  resultrecv = resultrecv - "</i>";
  resultrecv = resultrecv - "<BR>";

  banner = banner + resultrecv;
  banner = banner + string("\n");

  resultrecv = strstr(result, "Company Name");
  resultsub = strstr(resultrecv, string("\n"));
  resultrecv = resultrecv - resultsub;
  resultrecv = resultrecv - "<B>";
  resultrecv = resultrecv - "</B>";
  resultrecv = resultrecv - "<i>";
  resultrecv = resultrecv - "</i>";
  resultrecv = resultrecv - "<BR>";

  banner = banner + resultrecv;
  banner = banner + string("\n");

  resultrecv = strstr(result, "Web Server IP Address");
  resultsub = strstr(resultrecv, string("\n"));
  resultrecv = resultrecv - resultsub;
  resultrecv = resultrecv - "<B>";
  resultrecv = resultrecv - "</B>";
  resultrecv = resultrecv - "&nbsp;</CENTER>";

  banner = banner + resultrecv;
  banner = banner + string("\n");

  resultrecv = strstr(result, "Web Server Domain Name");
  resultsub = strstr(resultrecv, string("\n"));
  resultrecv = resultrecv - resultsub;
  resultrecv = resultrecv - "</B>";
  resultrecv = resultrecv - "&nbsp;</CENTER>";

  banner = banner + resultrecv;
  banner = banner + string("\n");

  security_message( port:port, data:banner );
  exit( 0 );
}

if( host_runs( "Windows" ) == "yes" )
  files = make_list( "/webplus.exe" );
else if( host_runs( "Linux" ) == "yes" )
  files = make_list( "/webplus" );
else
  files = make_list( "/webplus", "/webplus.exe" );

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( files ) {

    url = dir + file + "?about";
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req );

    if( "TalentSoft Web+" >< res || "TalentSoft Web" >< res ) {
      extract_version( result:res, port:port );
    }
  }
}

exit( 0 );
