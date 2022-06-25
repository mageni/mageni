###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_apcu_info.nasl 5798 2017-03-30 15:23:49Z cfi $
#
# APC / APCu INFO page accessible
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
 script_oid("1.3.6.1.4.1.25623.1.0.111025");
 script_version("$Revision: 5798 $");
 script_tag(name:"last_modification", value:"$Date: 2017-03-30 17:23:49 +0200 (Thu, 30 Mar 2017) $");
 script_tag(name:"creation_date", value:"2015-07-27 16:00:00 +0200 (Mon, 27 Jul 2015)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("APC / APCu INFO page accessible");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
 script_family("Web application abuses");
 script_dependencies("find_service.nasl", "http_version.nasl", "phpinfo.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "solution" , value : "Delete them or restrict access to the listened files.");
 script_tag(name : "summary" , value : "The APC / APCu INFO page is providing internal information
 about the system.");
 script_tag(name : "impact" , value : "Some of the information that could be gathered from this file 
 includes: The running APC/APCu version, the PHP version, the webserver version.");

 script_tag(name : "solution_type", value : "Workaround");

 script_tag(name: "qod_type", value: "remote_banner");

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

function get_php_version( data ) {
  if( isnull( data ) ) return;

  vers = eregmatch( pattern:'>PHP Version</td><td>([0-9.]+(-[0-9])?).*</td></tr>', string:data );
  if( isnull ( vers[1] ) ) return;

  return vers[1];

}

port = get_http_port( default:80 );

if( !can_host_php( port:port ) ) exit( 0 );

phpinfoVer = get_kb_item( 'php/phpinfo/phpversion/' + port );

files = make_list( "/index.php", "/apc.php", "/apcu.php", "/apcinfo.php" );

foreach dir( make_list_unique( "/", "/apc", "/cache", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( files ) {

    res = http_get_cache( item:string( dir, file ), port:port );
    if( res == NULL ) continue;

    if( "<title>APC INFO" >< res || "<title>APCu INFO" >< res ) {
      rep += dir + file + '\n';
      if( ! phpversion ) {
        phpversion = get_php_version( data:res );
      }
    }
  }
}

if( ! isnull( phpversion ) && isnull( phpinfoVer ) )
  set_kb_item( name:'php/phpinfo/phpversion/' + port, value:phpversion );

if( rep ) {
 report = string("The following files are providing a APC / APCu INFO page which disclose potentially sensitive information to the remote attacker : ", rep );
 security_message( port:port, data:report );
 exit( 0 );
}

exit( 99 );
