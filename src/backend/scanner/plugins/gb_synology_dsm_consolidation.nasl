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
  script_oid("1.3.6.1.4.1.25623.1.0.170202");
  script_version("2022-11-02T10:36:36+0000");
  script_tag(name:"last_modification", value:"2022-11-02 10:36:36 +0000 (Wed, 02 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-10-25 11:21:01 +0000 (Tue, 25 Oct 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Synology DiskStation Manager (DSM) Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_synology_dsm_http_detect.nasl", "gb_synology_dsm_srm_mdns_detect.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Consolidation of Synology NAS devices, DiskStation Manager
  (DSM) OS and application detections.");

  script_xref(name:"URL", value:"https://www.synology.com/en-us/dsm");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

if( ! get_kb_item( "synology/dsm/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...


detected_version = "unknown";
detected_model = "unknown";
location = "/";

foreach source( make_list( "http", "mdns" ) ) {
  version_list = get_kb_list( "synology/dsm/" + source + "/*/version" );
  foreach version( version_list ) {
    if( version != "unknown" && detected_version == "unknown" ) {
      detected_version = version;
      break;
    }
  }

  model_list = get_kb_list( "synology/dsm/" + source + "/*/model" );
  foreach model( model_list ) {
    if( model != "unknown" && detected_model == "unknown" ) {
      detected_model = model;
      break;
    }
  }
}

if( detected_model != "unknown" ) {
  os_app = "Synology DSM " + detected_model + " Firmware";
  os_cpe = "cpe:/o:synology:" + tolower( detected_model ) + "_firmware";
  hw_app = "Synology NAS " + detected_model + " Device";
  hw_cpe = "cpe:/h:synology:" + tolower( detected_model );
} else {
  os_app = "Synology NAS Unknown Model Firmware";
  os_cpe = "cpe:/o:synology:unknown_model_firmware";
  hw_app = "Synology NAS Unknown Model Device";
  hw_cpe = "cpe:/h:synology:unknown_model";
}

if( detected_version != "unknown" )
  os_cpe += ":" + detected_version;

# nb: since NVD registers this as multiple CPEs, used this a: for model agnostic registration
cpe = build_cpe( value:detected_version, exp:"^([0-9.-]+)", base:"cpe:/a:synology:diskstation_manager:" );
if( ! cpe )
  cpe = "cpe:/a:synology:diskstation_manager";

os_register_and_report( os:"Synology DiskStation Manager", cpe:os_cpe, port:0,
                        desc:"Synology DiskStation Manager (DSM) Detection Consolidation", runs_key:"unixoide" );

registered = FALSE;

if( http_ports = get_kb_list( "synology/dsm/http/port" ) ) {
  foreach port( http_ports ) {

    detection_methods += '\nHTTP(s) on port ' + port + '/tcp\n';

    concluded    = get_kb_item( "synology/dsm/http/" + port + "/concluded" );
    concludedUrl = get_kb_item( "synology/dsm/http/" + port + "/concludedUrl" );
    if( concluded && concludedUrl )
      detection_methods += "Concluded: " + concluded + '\nfrom URL(s):\n' + concludedUrl + '\n';
    else if( concludedUrl )
      detection_methods += "Concluded from URL(s):\n " + concludedUrl + '\n';

    register_product( cpe:hw_cpe, location:location, port:port, service:"www" );
    register_product( cpe:os_cpe, location:location, port:port, service:"www" );
    register_product( cpe:cpe, location:location, port:port, service:"www" );
    registered = TRUE;
  }
}

if( mdns_ports = get_kb_list( "synology/dsm/mdns/port" ) ) {
  foreach port( mdns_ports ) {
    detection_methods += '\nmDNS on port 5353/udp exposing service for ' + port + '/tcp\n';

    model = get_kb_item( "synology/dsm/mdns/" + port + "/model" );
    version = get_kb_item( "synology/dsm/mdns/" + port + "/version" );

    detection_methods += '\n  Model:                          ' + model;

    if( version )
      detection_methods += '\n  Version:                        ' + version;

    serial = get_kb_item( "synology/dsm/mdns/" + port + "/serial" );
    if( serial )
      detection_methods += '\n  Serial:                         ' + serial;
  }
  #nb: Although the service was discovered via mDNS, it actually resides on the TCP port exposed by mDNS
  if( ! registered ) { # nb: just making sure we only register once
    register_product( cpe:hw_cpe, location:location, port:port, service:"www"  );
    register_product( cpe:os_cpe, location:location, port:port, service:"www"  );
    register_product( cpe:cpe, location:location, port:port, service:"www" );
  }
}

report  = build_detection_report( app:os_app,
                                  version:detected_version,
                                  install:location,
                                  cpe:os_cpe );
report += '\n\n';
report += build_detection_report( app:hw_app,
                                  skip_version:TRUE,
                                  install:location,
                                  cpe:hw_cpe );
report += '\n\n';
report += build_detection_report( app:"Synology DiskStation Manager",
                                  skip_version:TRUE,
                                  install:location,
                                  cpe:cpe );

if( detection_methods )
  report += '\n\nDetection methods:\n' + detection_methods;

report = chomp( report );

log_message( port:0, data:chomp( report ) );

exit( 0 );
