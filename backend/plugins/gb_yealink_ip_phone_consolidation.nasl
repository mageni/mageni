##############################################################################
# OpenVAS Vulnerability Test
#
# Yealink IP Phone Detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113281");
  script_version("2020-08-11T09:37:56+0000");
  script_tag(name:"last_modification", value:"2020-08-12 10:28:50 +0000 (Wed, 12 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-10-30 13:19:10 +0100 (Tue, 30 Oct 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Yealink IP Phone Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Yealink IP Phone detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_yealink_ip_phone_sip_detect.nasl", "gb_yealink_ip_phone_http_detect.nasl");
  script_mandatory_keys("yealink_ipphone/detected");

  exit(0);
}

include( "cpe.inc" );
include( "host_details.inc" );

if( ! get_kb_item( "yealink_ipphone/detected" ) )
  exit( 0 );

detected_version = "unknown";
detected_model = "unknown";
location = "/";

foreach source( make_list( "sip", "http" ) ) {
  version_list = get_kb_list( "yealink_ipphone/" + source + "/*/version" );
  foreach version( version_list ) {
    if( version != "unknown" && detected_version == "unknown" ) {
      detected_version = version;
      break;
    }
  }

  model_list = get_kb_list( "yealink_ipphone/" + source + "/*/model" );
  foreach model( model_list ) {
    if( model != "unknown" && detected_model == "unknown" ) {
      detected_model = model;
      break;
    }
  }
}

if( detected_model != "unknown" ) {
  os_name = "Yealink IP Phone " + detected_model + " Firmware";
  hw_name = "Yealink IP Phone " + detected_model;
  hw_cpe = "cpe:/h:yealink:" + tolower(detected_model);
} else {
  os_name = "Yealink IP Phone Unknown Model Firmware";
  hw_name = "Yealink IP Phone Unknown Model";
  hw_cpe = "cpe:/h:yealink:voip_phone";
}

os_cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:yealink:voip_phone_firmware:" );
if( ! os_cpe )
  os_cpe = "cpe:/o:yealink:voip_phone_firmware";

register_and_report_os( os: os_name, cpe: os_cpe, desc: "Yealink IP Phone Detection Consolidation", runs_key: "unixoide" );

if( http_ports = get_kb_list( "yealink_ipphone/http/port" ) ) {
  foreach port( http_ports ) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item( "yealink_ipphone/http/" + port + "/concluded" );
    if( concluded )
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product( cpe: os_cpe, location: port + "/tcp", port: port, service: "www" );
    register_product( cpe: hw_cpe, location: port + "/tcp", port: port, service: "www" );
  }
}

if( sip_ports = get_kb_list( "yealink_ipphone/sip/port" ) ) {
  foreach port( sip_ports ) {
    proto = get_kb_item( "yealink_ipphone/sip/" + port + "/proto" );
    extra += 'SIP on port ' + port + '/' + proto + '\n';

    concluded = get_kb_item( "yealink_ipphone/sip/" + port + "/concluded" );
    if( concluded )
      extra += '  SIP Banner: ' + concluded + '\n';

    register_product( cpe: hw_cpe, location: location, port: port, service: "sip", proto: proto );
    register_product( cpe: os_cpe, location: location, port: port, service: "sip", proto: proto );
  }
}

report  = build_detection_report( app: os_name, version: detected_version, install: location, cpe: os_cpe );
report += '\n\n';
report += build_detection_report( app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe );

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message( port: 0, data: report );

exit(0);
