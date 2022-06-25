###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_detect.nasl 13811 2019-02-21 11:07:30Z cfischer $
#
# PHP Version Detection (Remote)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800109");
  script_version("$Revision: 13811 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 12:07:30 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2008-10-07 16:11:33 +0200 (Tue, 07 Oct 2008)");
  script_name("PHP Version Detection (Remote)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "gb_phpinfo_output_detect.nasl", "webmirror.nasl",
                      "sw_apcu_info.nasl", "gb_php_detect_lin.nasl", "secpod_php_detect_win.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of PHP.
  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

checkFiles = make_list();

port = get_http_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {
  if( dir == "/" ) dir = "";
  checkFiles = make_list( checkFiles, dir + "/", dir + "/index.php" );
}

phpFilesList = http_get_kb_file_extensions( port:port, host:host, ext:"php" );
if( phpFilesList && is_array( phpFilesList ) ) {
  count = 0;
  foreach phpFile( phpFilesList ) {
    count++;
    checkFiles = make_list_unique( checkFiles, phpFile );
    if( count >= 10 ) break; # TBD: Should be enough files to check, maybe we could even lower this to 5...
  }
}

foreach checkFile( checkFiles ) {

  banner = get_http_banner( port:port, file:checkFile );

  if( "PHP" >< banner ) {
    phpInfo = egrep( pattern:"Server.*PHP.*", string:banner, icase:FALSE );
    if( ! phpInfo ) {
      phpInfo = egrep( pattern:"X.Powered.By.*PHP.*", string:banner, icase:FALSE );
    }

    if( "PHPSESSID" >< banner ) phpSessId = TRUE;

    # PHP/5.6.0alpha1
    # PHP/5.6.0
    # X-Powered-By: PHP/7.0.30-0+deb9u1
    phpVer = ereg_replace( pattern:".*PHP/([.0-9A-Za-z]*).*", string:phpInfo, replace:"\1" );
    if( ! isnull( phpVer ) && phpVer != "" ) break;
  }
}

if( isnull( phpVer ) || phpVer == "" ) {
  # nb: Currently set by sw_apcu_info.nasl and gb_phpinfo_output_detect.nasl but could be extended by other PHP scripts providing such info
  phpscriptsUrls = get_kb_list( "php/banner/from_scripts/" + host + "/" + port + "/urls" );
  if( phpscriptsUrls && is_array( phpscriptsUrls ) ) {
    foreach phpscriptsUrl( phpscriptsUrls ) {
      _phpVer  = get_kb_item( "php/banner/from_scripts/" + host + "/" + port + "/short_versions/" + phpscriptsUrl );
      _phpInfo = get_kb_item( "php/banner/from_scripts/" + host + "/" + port + "/full_versions/" + phpscriptsUrl );
      if( _phpVer && _phpVer =~ "[0-9.]+" ) {
        phpVer   = _phpVer;
        phpInfo  = _phpInfo;
        conclUrl = report_vuln_url( port:port, url:phpscriptsUrl, url_only:TRUE ) + " (phpinfo()/ACP(u) output)";
        break; # TBD: Don't stop after the first hit? But that could report the very same PHP version if multiple scripts where found.
      }
    }
  }
}

if( phpVer || phpSessId ) {

  location = port + "/tcp";
  if( ! phpInfo && phpSessId )
    phpInfo = "PHPSESSID Session-Cookie";

  if( ! phpVer ) phpVer = "unknown";

  set_kb_item( name:"www/" + port + "/PHP", value:phpVer );
  set_kb_item( name:"php/installed", value:TRUE );

  # nb: To tell can_host_asp and can_host_php from http_func that the service support this
  replace_kb_item( name:"www/" + port + "/can_host_php", value:"yes" );

  cpe = build_cpe( value:phpVer, exp:"^([0-9.A-Za-z]+)", base:"cpe:/a:php:php:" );
  if( isnull( cpe ) || phpVer == "unknown" )
    cpe = "cpe:/a:php:php";

  register_product( cpe:cpe, location:location, port:port, service:"www" );

  log_message( data:build_detection_report( app:"PHP",
                                            version:phpVer,
                                            install:location,
                                            cpe:cpe,
                                            concludedUrl:conclUrl,
                                            concluded:phpInfo ),
                                            port:port );
}

exit( 0 );