###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-detect-WindowsSharepointServices.nasl 13762 2019-02-19 12:12:06Z cfischer $
#
# This script ensure that Windows SharePointServices is installed and running
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# TODO: implement service pack gathering using the minor version number
# source: http://www.microsoft.com/downloads/details.aspx?FamilyId=D51730B5-48FC-4CA2-B454-8DC2CAF93951&displaylang=en#Requirements
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
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
  script_oid("1.3.6.1.4.1.25623.1.0.101018");
  script_version("$Revision: 13762 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-19 13:12:06 +0100 (Tue, 19 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-04-01 22:29:14 +0200 (Wed, 01 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Windows SharePoint Services detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"It's recommended to allow connection to this host only from trusted hosts or networks.");

  script_tag(name:"summary", value:"The remote host is running Windows SharePoint Services.
  Microsoft SharePoint products and technologies include browser-based collaboration and a document-management platform.
  These can be used to host web sites that access shared workspaces and documents from a browser.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("misc_func.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_asp( port:port ) )
  exit( 0 );

# req a non existent random page
page = "vt-test" + rand() + ".aspx";

req = http_get( item:"/" + page, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( ! res || "microsoft" >!< tolower( res ) )
  exit( 0 );

dotNetServer = eregmatch( pattern:"Server: Microsoft-IIS/([0-9.]+)",string:res, icase:TRUE );
mstsVersion = eregmatch( pattern:"MicrosoftSharePointTeamServices: ([0-9.]+)",string:res, icase:TRUE );
xPoweredBy = eregmatch( pattern:"X-Powered-By: ([a-zA-Z.]+)",string:res, icase:TRUE );
aspNetVersion = eregmatch( pattern:"X-AspNet-Version: ([0-9.]+)",string:res, icase:TRUE );

if( mstsVersion ) {

  # TODO: extract the service pack using the [0-9] pattern (minor version number)
  wssVersion = '';

  set_kb_item( name:"WindowsSharePointServices/installed", value:TRUE );
  set_kb_item( name:"MicrosoftSharePointTeamServices/version", value:mstsVersion[1] );

  register_host_detail( name:"App", value:"cpe:/a:microsoft:sharepoint_team_services:2007" );

  if( eregmatch( pattern:"(6.0.2.[0-9]+)", string:mstsVersion[1], icase:TRUE ) ) {
    wssVersion = "2.0";
    set_kb_item( name:"WindowsSharePointServices/version", value:wssVersion );

    register_and_report_cpe( app:"WindowsSharePointServices", ver:wssVersion, base:"cpe:/a:microsoft:sharepoint_services:", expr:"^([0-9]\.[0-9])", regPort:port, insloc:"/" );
  }

  if( eregmatch( pattern:"(12.[0-9.]+)", string:mstsVersion[1], icase:TRUE ) ) {
    wssVersion = "3.0";
    set_kb_item( name:"WindowsSharePointServices/version", value:wssVersion) ;

    register_and_report_cpe( app:"WindowsSharePointServices", ver:wssVersion, base:"cpe:/a:microsoft:sharepoint_services:", expr:"^([0-9]\.[0-9])", regPort:port, insloc:"/" );
  }

  report = "Detected: " + mstsVersion[0];
  if( wssVersion )
    report += '\n' + "Windows SharePoint Services " + wssVersion;
}

if( dotNetServer ) {

  # OS fingerprint using IIS signature
  # https://en.wikipedia.org/wiki/Internet_Information_Services#History
  osVersion = '';
  if( dotNetServer[1] == "10.0" )
    osVersion = "Windows Server 2016 / Windows 10";

  if( dotNetServer[1] == "8.5" )
    osVersion = "Windows Server 2012 R2 / Windows 8.1";

  if( dotNetServer[1] == "8.0" )
    osVersion = "Windows Server 2012 / Windows 8";

  if( dotNetServer[1] == "7.5" )
    osVersion = "Windows Server 2008 R2 / Windows 7";

  if( dotNetServer[1] == "7.0" )
    osVersion = "Windows Server 2008 / Windows Vista";

  if( dotNetServer[1] == "6.0" )
    osVersion = "Windows Server 2003 / Windows XP Professional x64";

  if( dotNetServer[1] == "5.1" )
    osVersion = "Windows XP Professional";

  if( dotNetServer[1] == "5.0" )
    osVersion = "Windows 2000";

  if( dotNetServer[1] == "4.0" )
    osVersion = "Windows NT 4.0 Option Pack";

  if( dotNetServer[1] == "3.0" )
    osVersion = "Windows NT 4.0 SP2";

  if( dotNetServer[1] == "2.0" )
    osVersion = "Windows NT 4.0";

  if( dotNetServer[1] == "1.0" )
    osVersion = "Windows NT 3.51";

  report += '\n' + dotNetServer[0];
  if( osVersion ) {
    report += '\n' + "Operating System Type: " + osVersion;
  }
}

if( aspNetVersion ) {
  set_kb_item( name:"aspNetVersion/version", value:aspNetVersion[1] );
  report += '\n' + aspNetVersion[0];

  if( xPoweredBy ) {
    set_kb_item( name:"ASPX/enabled", value:TRUE );
    report += '\n' + xPoweredBy[0];
  }
}

if( strlen( report ) > 0 ) {
  log_message( port:port, data:report );
}

exit( 0 );