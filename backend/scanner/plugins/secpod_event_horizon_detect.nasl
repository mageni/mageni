###############################################################################
# OpenVAS Vulnerability Test
#
# Event Horizon Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902081");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Event Horizon Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Product detection");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("find_service.nasl", "http_version.nasl");

  script_tag(name:"summary", value:"This script finds the installed Event Horizon version and saves
  the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/eventhorizon", "/eventh", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  if( rcvRes =~ "HTTP/1.. 200" && ">Event Horizon<" >< rcvRes ) {

    version = "unknown";

    ver = eregmatch( pattern:">Version ([0-9.]+)", string:rcvRes );
    if( isnull( ver[1] ) ) {
      sndReq = http_get( item: dir + "/CHANGELOG", port:port );
      rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

      ver = eregmatch( pattern:"([0-9.]+)", string:rcvRes );
      if( ! isnull( ver[1] ) ) version = ver[1];
    } else {
      version = ver[1];
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/Event/Horizon/Ver", value:tmp_version );
    set_kb_item( name:"event_horizon/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:jared_meeker:event_horizon:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:jared_meeker:event_horizon';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Event Horizon",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
