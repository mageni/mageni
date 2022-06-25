##############################################################################
# OpenVAS Vulnerability Test
#
# FrontAccounting Version Detection
#
# Authors:
# Maneesh KB <kmaneesh@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900256");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2009-11-30 15:32:46 +0100 (Mon, 30 Nov 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("FrontAccounting Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of FrontAccounting and
  sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/frontaccount", "/account", "/", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item: dir + "/index.php", port:port );

  if( "<title>FrontAccounting" >< buf || "images/logo_frontaccounting.png" >< buf ) {

    version = "unknown";

    ver = eregmatch( pattern:"(FrontAccounting |Version )([0-9.]+) ?([a-zA-Z]+ ?[0-9]+?)?",
                     string:buf, icase:TRUE );
    if( ! isnull( ver[2] ) ) {
      if( ver[3] ) {
        ver[3] = ereg_replace( string: ver[3], pattern:" ", replace:"" );
        version = ver[2] + "." + ver[3];
      } else {
        version = ver[2];
      }
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/FrontAccounting", value:tmp_version );
    set_kb_item( name:"frontaccounting/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+) ?([a-zA-Z]+ ?[0-9]+?)?", base:"cpe:/a:frontaccounting:frontaccounting:" );
    if( ! cpe )
      cpe = "cpe:/a:frontaccounting:frontaccounting";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data: build_detection_report( app:"FrontAccounting",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded:ver[0] ),
                                               port:port );
  }
}

exit( 0 );
