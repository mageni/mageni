###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_prosafe_consolidation.nasl 10898 2018-08-10 13:38:13Z cfischer $
#
# NETGEAR ProSAFE Devices Detection Consolidation
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108307");
  script_version("$Revision: 10898 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:38:13 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-12-05 09:03:31 +0100 (Tue, 05 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NETGEAR ProSAFE Devices Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_netgear_prosafe_snmp_detect.nasl", "gb_netgear_prosafe_http_detect.nasl", "gb_netgear_prosafe_telnet_detect.nasl");
  script_mandatory_keys("netgear/prosafe/detected");

  script_tag(name:"summary", value:"The script reports a detected NETGEAR ProSAFE device including the
  version number and exposed services.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

if( ! get_kb_item( "netgear/prosafe/detected" ) ) exit( 0 );

detected_model      = "unknown";
detected_fw_version = "unknown";
detected_fw_build   = "unknown";

# nb: Telnet and HTTP are currently only providing the model
foreach source( make_list( "snmp", "http", "telnet" ) ) {

  fw_version_list = get_kb_list( "netgear/prosafe/" + source + "/*/fw_version" );
  foreach fw_version( fw_version_list ) {
    if( fw_version != "unknown" && detected_fw_version == "unknown" ) {
      detected_fw_version = fw_version;
      set_kb_item( name:"netgear/prosafe/fw_version", value:fw_version );
    }
  }

  model_list = get_kb_list( "netgear/prosafe/" + source + "/*/model" );
  foreach model( model_list ) {
    if( model != "unknown" && detected_model == "unknown" ) {
      detected_model = model;
      set_kb_item( name:"netgear/prosafe/model", value:model );
    }
  }

  fw_build_list = get_kb_list( "netgear/prosafe/" + source + "/*/fw_build" );
  foreach fw_build( fw_build_list ) {
    if( fw_build != "unknown" && detected_fw_build == "unknown" ) {
      detected_fw_build = fw_build;
      set_kb_item( name:"netgear/prosafe/fw_build", value:fw_build );
    }
  }
}

if( detected_model != "unknown" ) {
  hw_cpe   = "cpe:/h:netgear:" + tolower( detected_model );
  app_type = detected_model;
} else {
  hw_cpe = "cpe:/h:netgear:unknown_model";
  app_type = "Unknown";
}

os_cpe = "cpe:/o:netgear:prosafe_firmware";
if( detected_fw_version != "unknown" ) {
  os_cpe += ":" + detected_fw_version;
}

if( detected_fw_build != "unknown" ) {
  fw_extra = "Build " + detected_fw_build;
}

register_and_report_os( os:"NETGEAR ProSAFE Firmware", cpe:os_cpe, desc:"NETGEAR ProSAFE Devices Detection Consolidation", runs_key:"unixoide" );

location = "/";

if( snmp_ports = get_kb_list( "netgear/prosafe/snmp/port" ) ) {
  foreach port( snmp_ports ) {
    concluded = get_kb_item( "netgear/prosafe/snmp/" + port + "/concluded" );
    extra += "SNMP on port " + port + '/udp\n';
    if( concluded ) {
      extra += 'Concluded from SNMP SysDesc: ' + concluded + '\n';
    }
    register_product( cpe:hw_cpe, location:location, port:port, service:"snmp", proto:"udp" );
    register_product( cpe:os_cpe, location:location, port:port, service:"snmp", proto:"udp" );
  }
}

if( http_ports = get_kb_list( "netgear/prosafe/http/port" ) ) {
  foreach port( http_ports ) {
    concluded = get_kb_item( "netgear/prosafe/http/" + port + "/concluded" );
    extra += "HTTP(s) on port " + port + '/tcp\n';
    if( concluded ) {
      extra += 'Concluded from: ' + concluded + '\n';
    }
    register_product( cpe:hw_cpe, location:location, port:port, service:"www" );
    register_product( cpe:os_cpe, location:location, port:port, service:"www" );
  }
}

if( telnet_ports = get_kb_list( "netgear/prosafe/telnet/port" ) ) {
  foreach port( telnet_ports ) {
    concluded = get_kb_item( "netgear/prosafe/telnet/" + port + "/concluded" );
    extra += "Telnet on port " + port + '/tcp\n';
    if( concluded ) {
      extra += 'Concluded from: ' + concluded + '\n';
    }
    register_product( cpe:hw_cpe, location:location, port:port, service:"telnet" );
    register_product( cpe:os_cpe, location:location, port:port, service:"telnet" );
  }
}

report = build_detection_report( app:"NETGEAR ProSAFE Firmware",
                                 version:detected_fw_version,
                                 install:location,
                                 extra:fw_extra,
                                 cpe:os_cpe );
report += '\n\n' + build_detection_report( app:"NETGEAR ProSAFE " + app_type + " Device",
                                           install:location,
                                           cpe:hw_cpe,
                                           skip_version:TRUE );
if( extra ) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message( port:0, data:report );

exit( 0 );
