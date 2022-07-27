# Copyright (C) 2008 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800109");
  script_version("2021-04-13T14:13:08+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-14 10:27:53 +0000 (Wed, 14 Apr 2021)");
  script_tag(name:"creation_date", value:"2008-10-07 16:11:33 +0200 (Tue, 07 Oct 2008)");
  script_name("PHP Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "gb_phpinfo_output_detect.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "sw_apcu_info.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of PHP.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

checkFiles = make_list();

port = http_get_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {
  if( dir == "/" )
    dir = "";
  checkFiles = make_list( checkFiles, dir + "/", dir + "/index.php" );
}

phpFilesList = http_get_kb_file_extensions( port:port, host:host, ext:"php" );
if( phpFilesList && is_array( phpFilesList ) ) {
  count = 0;
  foreach phpFile( phpFilesList ) {
    count++;
    checkFiles = make_list_unique( checkFiles, phpFile );
    if( count >= 10 )
     break; # TBD: Should be enough files to check, maybe we could even lower this to 5...
  }
}

foreach checkFile( checkFiles ) {

  banner = http_get_remote_headers( port:port, file:checkFile );

  if( "PHP" >< banner ) {
    phpInfo = egrep( pattern:"Server.*PHP.*", string:banner, icase:FALSE );
    if( ! phpInfo )
      phpInfo = egrep( pattern:"X.Powered.By.*PHP.*", string:banner, icase:FALSE );

    if( "PHPSESSID" >< banner )
      phpSessId = TRUE;

    # PHP/5.6.0alpha1
    # PHP/5.6.0
    # X-Powered-By: PHP/7.0.30-0+deb9u1
    version = ereg_replace( pattern:".*PHP/([.0-9A-Za-z]*).*", string:phpInfo, replace:"\1" );
    if( ! isnull( version ) && version != "" )
      break;
  }
}

if( isnull( version ) || version == "" ) {
  # nb: Currently set by sw_apcu_info.nasl and gb_phpinfo_output_detect.nasl but could be extended by other PHP scripts providing such info
  phpscriptsUrls = get_kb_list( "php/banner/from_scripts/" + host + "/" + port + "/urls" );
  if( phpscriptsUrls && is_array( phpscriptsUrls ) ) {
    foreach phpscriptsUrl( phpscriptsUrls ) {
      _version  = get_kb_item( "php/banner/from_scripts/" + host + "/" + port + "/short_versions/" + phpscriptsUrl );
      _phpInfo = get_kb_item( "php/banner/from_scripts/" + host + "/" + port + "/full_versions/" + phpscriptsUrl );
      if( _version && _version =~ "[0-9.]+" ) {
        version   = _version;
        phpInfo  = _phpInfo;
        conclUrl = http_report_vuln_url( port:port, url:phpscriptsUrl, url_only:TRUE ) + " (phpinfo()/ACP(u) output)";
        break; # TBD: Don't stop after the first hit? But that could report the very same PHP version if multiple scripts were found.
      }
    }
  }
}

if( version || phpSessId ) {

  location = port + "/tcp";
  if( ! phpInfo && phpSessId )
    phpInfo = "PHPSESSID Session-Cookie";

  if( ! version )
    version = "unknown";

  set_kb_item( name:"www/" + port + "/PHP", value:version );
  set_kb_item( name:"php/detected", value:TRUE );

  # nb: To tell http_can_host_asp and http_can_host_php from http_func.inc that the service support this
  replace_kb_item( name:"www/" + port + "/can_host_php", value:"yes" );

  cpe = build_cpe( value:version, exp:"^([0-9.A-Za-z]+)", base:"cpe:/a:php:php:" );
  if( ! cpe )
    cpe = "cpe:/a:php:php";

  register_product( cpe:cpe, location:location, port:port, service:"www" );

  log_message( data:build_detection_report( app:"PHP",
                                            version:version,
                                            install:location,
                                            cpe:cpe,
                                            concludedUrl:conclUrl,
                                            concluded:phpInfo ),
                                            port:port );
}

exit( 0 );
