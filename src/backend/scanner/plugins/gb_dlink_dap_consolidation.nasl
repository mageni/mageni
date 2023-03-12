# Copyright (C) 2023 Greenbone Networks GmbH
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

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170325");
  script_version("2023-03-06T10:10:03+0000");
  script_tag(name:"last_modification", value:"2023-03-06 10:10:03 +0000 (Mon, 06 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-02-27 21:15:15 +0000 (Mon, 27 Feb 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("D-Link DAP Device Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Product detection");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_dlink_devices_hnap_detect.nasl",
                        "gsf/gb_dlink_devices_upnp_detect.nasl",
                        "gsf/gb_dlink_devices_mdns_detect.nasl");
  script_mandatory_keys("d-link/dap/detected");

  script_tag(name:"summary", value:"Consolidation of D-Link DAP devices detections.");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

if( ! get_kb_item( "d-link/dap/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...
detection_methods = "";
fw_version = "unknown";
hw_version = "unknown";
detected_model = "unknown";
location = "/";

foreach source( make_list( "hnap", "upnp", "mdns" ) ) {
  version_list = get_kb_list( "d-link/dap/" + source + "/*/fw_version" );
  foreach version( version_list ) {
    if( version != "unknown" && fw_version == "unknown" ) {
      fw_version = version;
      break;
    }
  }

  hw_version_list = get_kb_list( "d-link/dap/" + source + "/*/hw_version" );
  foreach version( hw_version_list ) {
    if( version != "unknown" && hw_version == "unknown" ) {
      hw_version = version;
      break;
    }
  }

  model_list = get_kb_list( "d-link/dap/" + source + "/*/model" );
  foreach model( model_list ) {
    if( model != "unknown" && detected_model == "unknown" ) {
      detected_model = model;
      break;
    }
  }
}

os_app = "D-Link DAP";
os_cpe = "cpe:/o:d-link:dap";
hw_app = "D-Link DAP";
hw_cpe = "cpe:/h:d-link:dap";

if( detected_model != "unknown" ) {
  os_app += "-" + detected_model + " Firmware";
  os_cpe += "-" + tolower( detected_model ) + "_firmware";
  hw_app += "-" + detected_model + " Device";
  hw_cpe += "-" + tolower( detected_model );
  set_kb_item( name:"d-link/dap/model", value:detected_model );
} else {
  os_app += " Unknown Model Firmware";
  os_cpe += "-unknown_model_firmware";
  hw_app += " Unknown Model Device";
  hw_cpe += "-unknown_model";
}

if( fw_version != "unknown" ) {
  os_cpe += ":" + fw_version;
  set_kb_item( name:"d-link/dap/fw_version", value:fw_version );
}

if( hw_version != "unknown" ) {
  hw_cpe += ":" + tolower( hw_version );
  set_kb_item( name:"d-link/dap/hw_version", value:hw_version );
}

register_port = 0;

if( http_ports = get_kb_list( "d-link/dap/hnap/port" ) ) {
  foreach port( http_ports ) {

    detection_methods += '\nHNAP on port ' + port + '/tcp\n';

    fw_concluded = get_kb_item( "d-link/dap/hnap/" + port + "/fw_concluded" );

    if( fw_concluded )
      detection_methods += "  Firmware concluded:  " + fw_concluded + '\n';

    hw_concluded    = get_kb_item( "d-link/dap/hnap/" + port + "/hw_concluded" );
    if( hw_concluded )
      detection_methods += "  Hardware version concluded:  " + hw_concluded + '\n';

    conclurl = get_kb_item( "d-link/dap/hnap/" + port + "/conclurl" );
    if( conclurl )
      detection_methods += '  from URL(s):\n    ' + conclurl + '\n';

    # nb: HNAP resides on same port as the Web App, so only register is no HTTP detection existed
    if( ! register_port ) {
      register_port = port;
      register_product( cpe:hw_cpe, location:location, port:register_port, service:"www" );
      register_product( cpe:os_cpe, location:location, port:register_port, service:"www" );
    }
  }
  # nb: to be used for active checks
  set_kb_item( name:"d-link/http/detected", value:TRUE );
}

if( mdns_ports = get_kb_list( "d-link/dap/mdns/port" ) ) {
  foreach port( mdns_ports ) {
    mdns_port_and_proto = get_kb_item( "d-link/dap/mdns/" + port + "/mdns_port_and_proto" );

    detection_methods += '\nmDNS on port ' + mdns_port_and_proto + " exposing service for " + port + '/tcp\n';

    concluded = get_kb_item( "d-link/dap/mdns/" + port + "/concluded" );
    if( concluded )
      detection_methods += '  Concluded from:' + concluded;
  }
  # nb: mDNS unually points to the HNAP port, so only register when not registered before
  if( ! register_port && port ) {
    register_port = port;
    register_product( cpe:hw_cpe, location:location, port:register_port, service:"www" );
    register_product( cpe:os_cpe, location:location, port:register_port, service:"www" );
  }
}

if( upnp_ports = get_kb_list( "d-link/dap/upnp/port" ) ) {
  foreach port( upnp_ports ) {
    detection_methods += '\nUPnP on port ' + port + '/tcp\n';

    concluded = get_kb_item( "d-link/dap/upnp/" + port + "/concluded" );
    if ( concluded ) {
      detection_methods += '  Concluded:' + concluded;
      concludedurl = get_kb_item( "d-link/dap/upnp/" + port + "/concludedUrl" );
      if ( concludedurl )
        detection_methods += '\n  from URL:\n    ' + concludedurl;
    }
  }
  # nb: uPnP might point to a different port than the registered one
  if( ! register_port || register_port >< port ) {
    register_product( cpe:hw_cpe, location:location, port:port, service:"upnp" );
    register_product( cpe:os_cpe, location:location, port:port, service:"upnp" );
  }
}

# nb: For cases when a generic key is needed
set_kb_item( name:"d-link/detected", value:TRUE );

os_register_and_report( os:os_app, cpe:os_cpe, port:port, desc:"D-Link DAP Devices Detection Consolidation", runs_key:"unixoide" );

report  = build_detection_report( app:os_app,
                                  version:fw_version,
                                  install:location,
                                  cpe:os_cpe );
report += '\n\n';
report += build_detection_report( app:hw_app,
                                  version:hw_version,
                                  install:location,
                                  cpe:hw_cpe );

if( detection_methods )
  report += '\n\nDetection methods:\n' + detection_methods;

log_message( port:0, data:chomp( report ) );

exit( 0 );
