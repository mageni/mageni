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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170300");
  script_version("2023-02-03T10:10:17+0000");
  script_tag(name:"last_modification", value:"2023-02-03 10:10:17 +0000 (Fri, 03 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-01-27 12:01:02 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Axis Device Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_dlink_dir_http_detect.nasl");
  script_mandatory_keys("axis/device/detected");

  script_tag(name:"summary", value:"Consolidation of Axis devices detections.");

  script_xref(name:"URL", value:"https://www.axis.com/");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

if( ! get_kb_item( "axis/device/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...
detection_methods = "";
version = "unknown";
detected_model = "unknown";
detected_model_name = "unknown";
location = "/";

foreach source( make_list( "http" ) ) {
  version_list = get_kb_list( "axis/device/" + source + "/*/version" );
  foreach vers( version_list ) {
    if( vers != "unknown" && version == "unknown" ) {
      version = vers;
      break;
    }
  }

  model_list = get_kb_list( "axis/device/" + source + "/*/model" );
  foreach model( model_list ) {
    if( model != "unknown" && detected_model == "unknown" ) {
      detected_model = model;
      break;
    }
  }

  model_name_list = get_kb_list( "axis/device/" + source + "/*/modelName" );
  foreach model_name( model_name_list ) {
    if( model_name != "unknown" && detected_model_name == "unknown" ) {
      detected_model_name = model_name;
      break;
    }
  }
}
# nb: Just a safety measure to have a model name. Not found as a real case so far.
if ( detected_model_name == "unknown" && detected_model != "unknown" )
  detected_model_name = detected_model;

is_axis_os = get_kb_item( "axis/device/axisos" );

os_cpe = "cpe:/o:axis:";
hw_cpe = "cpe:/h:axis:";

cpe_model = tolower( detected_model );
cpe_model = str_replace( string:cpe_model, find:" ", replace:"_" );

if ( is_axis_os ) {
  os_app = "AXIS OS";
  os_cpe += "axis_os";
} else {
  if( detected_model != "unknown" ) {
    os_app = detected_model_name + " Firmware";
    os_cpe += cpe_model + "_firmware";
  } else {
    os_app = "AXIS Unknown Model Firmware";
    os_cpe += "unknown_model_firmware";
  }
}

if( detected_model != "unknown" ) {
  hw_app += detected_model_name + " Device";
  hw_cpe += cpe_model;
  set_kb_item( name:"axis/device/model", value:detected_model );
} else {
  hw_app = "AXIS Unknown Model Device";
  hw_cpe += "unknown_model";
}

if( version != "unknown" )
  os_cpe += ":" + version;

os_register_and_report( os:os_app, cpe:os_cpe, port:0,
                        desc:"Axis Device Detection Consolidation", runs_key:"unixoide" );

if( http_ports = get_kb_list( "axis/device/http/port" ) ) {
  foreach port( http_ports ) {
    detection_methods += '\nHTTP(s) on port ' + port + '/tcp\n';
    concluded = get_kb_item( "axis/device/http/" + port + "/concluded" );
    conclurl = get_kb_item( "axis/device/http/" + port + "/concludedUrl" );
    if( concluded && conclurl )
      detection_methods += '  Firmware concluded:\n' + concluded + '\n  from URL(s):\n' + conclurl + '\n';
    else if( concluded )
      detection_methods += '  Firmware concluded:\n' + concluded + '\n';

    register_product( cpe:hw_cpe, location:location, port:port, service:"www" );
    register_product( cpe:os_cpe, location:location, port:port, service:"www" );
  }
}

report  = build_detection_report( app:os_app,
                                  version:version,
                                  install:location,
                                  cpe:os_cpe );
report += '\n\n';
report += build_detection_report( app:hw_app,
                                  skip_version:TRUE,
                                  install:location,
                                  cpe:hw_cpe );

if( detection_methods )
  report += '\n\nDetection methods:\n' + detection_methods;

log_message( port:0, data:chomp( report ) );

exit( 0 );
