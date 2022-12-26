# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.170230");
  script_version("2022-12-01T10:11:22+0000");
  script_tag(name:"last_modification", value:"2022-12-01 10:11:22 +0000 (Thu, 01 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-11-17 13:45:45 +0000 (Thu, 17 Nov 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Synology Router / Router Manager (SRM) Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_synology_srm_http_detect.nasl", "gb_synology_dsm_srm_mdns_detect.nasl",
                      "gb_synology_dsm_srm_upnp_detect.nasl");
  script_mandatory_keys("synology/srm/detected");

  script_tag(name:"summary", value:"Consolidation of Synology router devices, Router Manager
  (SRM) OS and manager application detections.");

  script_xref(name:"URL", value:"https://www.synology.com/en-us/srm");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");

if( ! get_kb_item( "synology/srm/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

detected_version = "unknown";
detected_model = "unknown";
location = "/";

foreach source( make_list( "http", "upnp", "mdns" ) ) {
  version_list = get_kb_list( "synology/srm/" + source + "/*/version" );
  foreach version( version_list ) {
    if( version != "unknown" && detected_version == "unknown" ) {
      detected_version = version;
      break;
    }
  }

  model_list = get_kb_list( "synology/srm/" + source + "/*/model" );
  foreach model( model_list ) {
    if( model != "unknown" && detected_model == "unknown" ) {
      detected_model = model;
      break;
    }
  }
}

if( detected_model != "unknown" ) {
  hw_app = "Synology Router " + detected_model + " Device";
  hw_cpe = "cpe:/h:synology:" + tolower( detected_model );
}

os_cpe = build_cpe( value:detected_version, exp:"^([0-9.-]+)", base:"cpe:/o:synology:router_manager_firmware:" );
if( ! os_cpe )
  os_cpe = "cpe:/o:synology:router_manager_firmware";

# nb: since NVD registers this as multiple CPEs, used this a: for model agnostic registration
cpe = build_cpe( value:detected_version, exp:"^([0-9.-]+)", base:"cpe:/a:synology:router_manager:" );
if( ! cpe )
  cpe = "cpe:/a:synology:router_manager";

os_register_and_report( os:"Synology Router Manager", cpe:os_cpe, port:0,
                        desc:"Synology Router / Router Manager (SRM) Detection Consolidation", runs_key:"unixoide" );

registered = FALSE;
register_port = 0;

if( http_ports = get_kb_list( "synology/srm/http/port" ) ) {
  foreach port( http_ports ) {

    detection_methods += '\n\nHTTP(s) on port ' + port + "/tcp";

    concluded    = get_kb_item( "synology/srm/http/" + port + "/concluded" );
    concludedUrl = get_kb_item( "synology/srm/http/" + port + "/concludedUrl" );
    if( concluded && concludedUrl )
      detection_methods += '\nConcluded:' + concluded + '\nfrom URL(s):\n' + concludedUrl;
    else if( concludedUrl )
      detection_methods += '\nConcluded from URL(s):\n' + concludedUrl;
    register_port = port;
    registered = TRUE;
  }
}

if( mdns_ports = get_kb_list( "synology/srm/mdns/port" ) ) {
  foreach port( mdns_ports ) {
    detection_methods += '\n\nmDNS on port 5353/udp exposing service for ' + port + "/tcp";

    model = get_kb_item( "synology/srm/mdns/" + port + "/model" );
    if( model )
      detection_methods += '\n  Model:  ' + model;

    serial = get_kb_item( "synology/srm/mdns/" + port + "/serial" );
    if( serial )
      detection_methods += '\n  Serial: ' + serial;
  }
  #nb: Although the service was discovered via mDNS, it actually resides on the TCP port exposed by mDNS
  if( ! registered ) {
    register_port = port;
    registered = TRUE;
  }
}

if( upnp_ports = get_kb_list( "synology/srm/upnp/port" ) ) {
  foreach port( upnp_ports ) {
    detection_methods += '\n\nUPnP on port ' + port + "/tcp";

    model = get_kb_item( "synology/srm/upnp/" + port + "/model" );
    if( model )
      detection_methods += '\n  Model:   ' + model;

    version = get_kb_item( "synology/srm/upnp/" + port + "/version" );
    if( version )
      detection_methods += '\n  Version: ' + version;

    upnp_loc = get_kb_item( "upnp/tcp/" + port + "/location" );
    if( upnp_loc )
      detection_methods += '\nfrom URL:\n  ' + http_report_vuln_url( port:port, url:upnp_loc, url_only:TRUE );
  }

  if( ! registered ) {
    register_port = port;
    registered = TRUE;
  }
}

if ( hw_cpe )
  register_product( cpe:hw_cpe, location:location, port:register_port, service:"www" );
register_product( cpe:os_cpe, location:location, port:register_port, service:"www" );
register_product( cpe:cpe, location:location, port:register_port, service:"www" );

report  = build_detection_report( app:"Synology Router Firmware",
                                  version:detected_version,
                                  install:location,
                                  cpe:os_cpe );
report += '\n\n';
if ( hw_cpe ) {
  report += build_detection_report( app:hw_app,
                                    skip_version:TRUE,
                                    install:location,
                                    cpe:hw_cpe );
  report += '\n\n';
}
report += build_detection_report( app:"Synology Router Manager",
                                  skip_version:TRUE,
                                  install:location,
                                  cpe:cpe );

if( detection_methods )
  report += '\n\nDetection methods:' + detection_methods;

log_message( port:0, data:chomp( report ) );

exit( 0 );
