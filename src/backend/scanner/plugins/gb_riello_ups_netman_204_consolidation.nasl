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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104593");
  script_version("2023-03-08T10:08:50+0000");
  script_tag(name:"last_modification", value:"2023-03-08 10:08:50 +0000 (Wed, 08 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-07 07:51:46 +0000 (Tue, 07 Mar 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Riello UPS / NetMan 204 Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_riello_ups_netman_204_http_detect.nasl");
  script_mandatory_keys("riello/netman_204/detected");

  script_xref(name:"URL", value:"https://www.riello-ups.com/products/4-software-connectivity/85-netman-204");

  script_tag(name:"summary", value:"Consolidation of Riello NetMan 204 network cards and the
  underlying uninterruptible power supply (UPS) device detections.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

if( ! get_kb_item( "riello/netman_204/detected" ) )
  exit( 0 );

detected_ups_model = "unknown";
detected_ups_fw_version = "unknown";
detected_netman_app_version = "unknown";
detected_netman_sys_version = "unknown";

foreach source( make_list( "http" ) ) {
  ups_model_list = get_kb_list( "riello/netman_204/" + source + "/*/ups_model" );
  foreach ups_model( ups_model_list ) {
    if( ups_model != "unknown" && detected_ups_model == "unknown" ) {
      detected_ups_model = ups_model;
      set_kb_item( name:"riello/ups/model", value:detected_ups_model );
      break;
    }
  }

  ups_fw_vers_list = get_kb_list( "riello/netman_204/" + source + "/*/ups_fw_version" );
  foreach ups_fw_vers( ups_fw_vers_list ) {
    if( ups_fw_vers != "unknown" && detected_ups_fw_version == "unknown" ) {
      detected_ups_fw_version = ups_fw_vers;
      set_kb_item( name:"riello/ups/firmware_version", value:detected_ups_fw_version );
      break;
    }
  }

  netman_sys_vers_list = get_kb_list( "riello/netman_204/" + source + "/*/netman_sys_version" );
  foreach netman_sys_vers( netman_sys_vers_list ) {
    if( netman_sys_vers != "unknown" && detected_netman_sys_version == "unknown" ) {
      detected_netman_sys_version = netman_sys_vers;
      set_kb_item( name:"riello/netman_204/sys_version", value:detected_netman_sys_version );
      break;
    }
  }

  netman_app_vers_list = get_kb_list( "riello/netman_204/" + source + "/*/netman_app_version" );
  foreach netman_app_vers( netman_app_vers_list ) {
    if( netman_app_vers != "unknown" && detected_netman_app_version == "unknown" ) {
      detected_netman_app_version = netman_app_vers;
      set_kb_item( name:"riello/netman_204/app_version", value:detected_netman_app_version );
      break;
    }
  }
}

netman_hw_name = "Riello NetMan 204";
netman_hw_cpe = "cpe:/h:riello-ups:netman_204";

if( detected_ups_model != "unknown" ) {
  ups_hw_name = "Riello " + detected_ups_model + " UPS";
  ups_hw_cpe = "cpe:/h:riello-ups:" + tolower( detected_ups_model );
} else {
  ups_hw_name = "Riello Unknown UPS Model";
  ups_hw_cpe = "cpe:/h:riello-ups:unknown_model";
}

# The "firmware" version of the UPS is added to the hardware CPE of it
if( detected_ups_fw_version != "unknown" )
  ups_hw_cpe += ":" + tolower( detected_ups_fw_version );

netman_os_name = "Riello NetMan 204 Firmware";
netman_os_cpe = "cpe:/o:riello-ups:netman_204_firmware";

# nb: We're assuming the System version as the OS version for now until otherwise determined that
# the Application version should be used instead
if( detected_netman_sys_version != "unknown" )
  netman_os_cpe += ":" + tolower( detected_netman_sys_version );

# nb: "Application version" might be the version of the web app
netman_app_name = "Riello NetMan 204 Application";
netman_app_cpe = "cpe:/a:riello-ups:netman_204";
if( detected_netman_app_version != "unknown" )
  netman_app_cpe += ":" + tolower( detected_netman_app_version );

os_register_and_report( os:netman_os_name, cpe:netman_os_cpe, port:0, desc:"Riello UPS / NetMan 204 Detection Consolidation", runs_key:"unixoide" );

install = "/";

if( http_ports = get_kb_list( "riello/netman_204/http/port" ) ) {
  foreach port( http_ports ) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item( "riello/netman_204/http/" + port + "/concluded" );
    if( concluded )
      extra += '  Concluded from version/product identification result:' + concluded + '\n';

    concUrl = get_kb_item( "riello/netman_204/http/" + port + "/concludedUrl" );
    if( concUrl )
      extra += '  Concluded from version/product identification location:\n' + concUrl + '\n';

    register_product( cpe:netman_os_cpe, location:install, port:port, service:"www" );
    register_product( cpe:netman_hw_cpe, location:install, port:port, service:"www" );
    register_product( cpe:ups_hw_cpe, location:install, port:port, service:"www" );
    register_product( cpe:netman_app_cpe, location:install, port:port, service:"www" );
  }
}

report = build_detection_report( app:netman_os_name, version:detected_netman_sys_version, install:install, cpe:netman_os_cpe );
report += '\n\n';
report += build_detection_report( app:netman_hw_name, skip_version:TRUE, install:install, cpe:netman_hw_cpe );
report += '\n\n';
report += build_detection_report( app:ups_hw_name, version:detected_ups_fw_version, install:install, cpe:ups_hw_cpe );
report += '\n\n';
report += build_detection_report( app:netman_app_name, version:detected_netman_app_version, install:install, cpe:netman_app_cpe );

if( extra ) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message( port:0, data:chomp( report ) );

exit( 0 );
