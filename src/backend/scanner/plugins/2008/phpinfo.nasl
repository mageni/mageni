###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpinfo.nasl 6355 2017-06-16 08:59:27Z cfischer $
#
# phpinfo() output accessible
#
# Authors:
# Randy Matz <rmatz@ctusa.net>
#
# Copyright:
# Copyright (C) 2003 Randy Matz
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
  script_oid("1.3.6.1.4.1.25623.1.0.312704");
  script_version("$Revision: 6355 $");
  script_tag(name:"last_modification", value:"$Date: 2017-06-16 10:59:27 +0200 (Fri, 16 Jun 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("phpinfo() output accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Randy Matz");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Delete them or restrict access to the listened files.");

  script_tag(name:"summary", value:"Many PHP installation tutorials instruct the user to create
  a file called phpinfo.php or similar containing the phpinfo() statement. Such a file is often times
  left in webserver directory after completion.");

  script_tag(name:"impact", value:"Some of the information that can be gathered from this file includes:

  The username of the user who installed php, if they are a SUDO user, the IP address of the host, the web server 
  version, the system version(unix / linux), and the root directory of the web server.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

function get_php_version( data ) {

  local_var data, vers;

  if( isnull( data ) ) return;

  vers = eregmatch( pattern:'>PHP Version ([^<]+)<', string:data );
  if( isnull ( vers[1] ) ) return;

  return vers[1];
}

report = 'The following files are calling the function phpinfo() which disclose potentially sensitive information to the remote attacker:\n';
files = make_list( "/phpinfo.php", "/info.php", "/test.php", "/php_info.php", "/index.php" );

port = get_http_port( default:80 );
# nb: Don't use can_host_php() here as this NVT is reporting PHP as well
# and can_host_php() could fail if no PHP was detected before

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( files ) {

    url = dir + file;

    res = http_get_cache( item:url, port:port );

    if( "<title>phpinfo()</title>" >< res ) {
      vuln = TRUE;
      report += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE );
      set_kb_item( name:"phpinfo/" + port + "/found", value:url );
      if( ! phpversion ) {
        phpversion = get_php_version( data:res );
      }
    }
  }
}

if( ! isnull( phpversion ) )
  set_kb_item( name:'php/phpinfo/phpversion/' + port, value:phpversion );

if( vuln ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
