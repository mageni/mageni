###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hirschmann_consolidation.nasl 8449 2018-01-17 17:04:52Z cfischer $
#
# Hirschmann Devices Detection Consolidation
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
  script_oid("1.3.6.1.4.1.25623.1.0.108311");
  script_version("$Revision: 8449 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 18:04:52 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-12-11 11:03:31 +0100 (Mon, 11 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Hirschmann Devices Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_hirschmann_webui_detect.nasl", "gb_hirschmann_snmp_detect.nasl", "gb_hirschmann_telnet_detect.nasl");
  script_mandatory_keys("hirschmann_device/detected");

  script_tag(name:"summary", value:"The script reports a detected Hirschmann device including the
  version number and exposed services.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

if( ! get_kb_item( "hirschmann_device/detected" ) ) exit( 0 );

detected_fw_version    = "unknown";
detected_product_name  = "unknown";
detected_platform_name = "unknown";

foreach source( make_list( "http", "telnet", "snmp" ) ) {

  fw_version_list = get_kb_list( "hirschmann_device/" + source + "/*/fw_version" );
  foreach fw_version( fw_version_list ) {
    if( fw_version != "unknown" && detected_fw_version == "unknown" ) {
      detected_fw_version = fw_version;
      set_kb_item( name:"hirschmann_device/fw_version", value:fw_version );
    }
  }

  product_name_list = get_kb_list( "hirschmann_device/" + source + "/*/product_name" );
  foreach product_name( product_name_list ) {
    if( product_name != "unknown" && detected_product_name == "unknown" ) {
      detected_product_name = product_name;
      set_kb_item( name:"hirschmann_device/product_name", value:product_name );
    }
  }

  platform_name_list = get_kb_list( "hirschmann_device/" + source + "/*/platform_name" );
  foreach platform_name( platform_name_list ) {
    if( platform_name != "unknown" && detected_platform_name == "unknown" ) {
      detected_platform_name = platform_name;
      set_kb_item( name:"hirschmann_device/platform_name", value:platform_name );
    }
  }
}

hw_cpe = "cpe:/h:belden:hirschmann";
if( detected_product_name != "unknown" ) {
  _detected_product_name = str_replace( string:detected_product_name, find:" ", replace:"_" );
  _detected_product_name = tolower( _detected_product_name );
  hw_cpe += "_" + _detected_product_name;
  hw_type = detected_product_name;
} else {
  hw_cpe += "_unknown_model";
  hw_type = "Unknown Model";
}

sw_cpe = "cpe:/a:belden:hirschmann";
if( detected_platform_name != "unknown" ) {
  sw_cpe += "_" + tolower( detected_platform_name );
  sw_type = detected_platform_name + " Platform";
} else {
  sw_cpe += "_unknown_platform";
  sw_type = "Unknown Platform";
}

os_cpe = "cpe:/o:belden:hirschmann_firmware";
if( detected_fw_version != "unknown" ) {
  sw_cpe += ":" + detected_fw_version;
  os_cpe += ":" + detected_fw_version;
}

register_and_report_os( os:"Belden Hirschmann Firmware", cpe:os_cpe, desc:"Hirschmann Devices Detection Consolidation", runs_key:"unixoide" );

location = "/";

if( http_ports = get_kb_list( "hirschmann_device/http/port" ) ) {
  foreach port( http_ports ) {
    concluded = get_kb_item( "hirschmann_device/http/" + port + "/concluded" );
    extra += "HTTP(s) on port " + port + '/tcp\n';
    if( concluded ) {
      extra += 'Concluded from: ' + concluded + '\n';
    }
    register_product( cpe:hw_cpe, location:location, port:port, service:"www" );
    register_product( cpe:os_cpe, location:location, port:port, service:"www" );
    register_product( cpe:sw_cpe, location:location, port:port, service:"www" );
  }
}

if( telnet_ports = get_kb_list( "hirschmann_device/telnet/port" ) ) {
  foreach port( telnet_ports ) {
    concluded = get_kb_item( "hirschmann_device/telnet/" + port + "/concluded" );
    extra += "Telnet on port " + port + '/tcp\n';
    if( concluded ) {
      extra += 'Concluded from: ' + concluded + '\n';
    }
    register_product( cpe:hw_cpe, location:location, port:port, service:"telnet" );
    register_product( cpe:os_cpe, location:location, port:port, service:"telnet" );
    register_product( cpe:sw_cpe, location:location, port:port, service:"telnet" );
  }
}

if( snmp_ports = get_kb_list( "hirschmann_device/snmp/port" ) ) {
  foreach port( snmp_ports ) {
    concluded    = get_kb_item( "hirschmann_device/snmp/" + port + "/concluded" );
    concludedOID = get_kb_item( "hirschmann_device/snmp/" + port + "/concludedOID" );
    extra += "SNMP on port " + port + '/udp\n';
    if( concluded && concludedOID ) {
      extra += 'Concluded from ' + concluded + ' via OID: ' + concludedOID + '\n';
    } else if( concluded ) {
      extra += 'Concluded from SNMP SysDesc: ' + concluded + '\n';
    }
    register_product( cpe:hw_cpe, location:location, port:port, service:"snmp", proto:"udp" );
    register_product( cpe:os_cpe, location:location, port:port, service:"snmp", proto:"udp" );
    register_product( cpe:sw_cpe, location:location, port:port, service:"snmp", proto:"udp" );
  }
}

report = build_detection_report( app:"Belden Hirschmann Firmware",
                                 version:detected_fw_version,
                                 install:location,
                                 cpe:os_cpe );

report += '\n\n' + build_detection_report( app:"Hirschmann " + hw_type,
                                           version:detected_fw_version,
                                           install:location,
                                           cpe:hw_cpe );

report += '\n\n' + build_detection_report( app:"Hirschmann " + sw_type,
                                           version:detected_fw_version,
                                           install:location,
                                           cpe:sw_cpe );

if( extra ) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message( port:0, data:report );

exit( 0 );
