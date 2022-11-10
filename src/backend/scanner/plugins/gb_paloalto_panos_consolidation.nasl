# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105263");
  script_version("2022-11-09T13:48:28+0000");
  script_tag(name:"last_modification", value:"2022-11-09 13:48:28 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"creation_date", value:"2015-04-22 14:02:11 +0200 (Wed, 22 Apr 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Palo Alto PAN-OS Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_paloalto_panos_http_detect.nasl",
                      "gb_paloalto_panos_api_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_paloalto_panos_snmp_detect.nasl",
                        "gsf/gb_paloalto_panos_ssh_login_detect.nasl");
  script_mandatory_keys("palo_alto/detected");

  script_tag(name:"summary", value:"Consolidation of Palo Alto PAN-OS detections.");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

if( ! get_kb_item( "palo_alto/detected" ) )
  exit( 0 );

detected_fw_version = "unknown";
detected_fw_hotfix  = "unknown";
detected_model      = "unknown";
ssh_concluded       = "";
xml_api_concluded   = "";
location = "/";

foreach source( make_list( "ssh-login", "snmp", "xml-api", "http" ) ) {
  model_list = get_kb_list( "palo_alto/" + source + "/*/model" );
  foreach model( model_list ) {
    if( model != "unknown" && detected_model == "unknown" ) {
      detected_model = model;
      break;
    }
  }

  version_list = get_kb_list( "palo_alto/" + source + "/*/version" );
  foreach version( version_list ) {
    if( version != "unknown" && detected_fw_version == "unknown" ) {
      detected_fw_version = version;
      if( "-h" >< detected_fw_version ) {
        version_and_hotfix  = split( detected_fw_version, sep:"-h", keep:FALSE );
        detected_fw_version = version_and_hotfix[0];
        detected_fw_hotfix  = version_and_hotfix[1];
      }
      break;
    }
  }
}

os_app = "Palo Alto PAN-OS";
os_cpe = "cpe:/o:paloaltonetworks:pan-os";
hw_app = "Palo Alto";
hw_cpe = "cpe:/h:paloaltonetworks";

if( detected_fw_version != "unknown" ) {
  set_kb_item( name:"palo_alto_pan_os/version", value:detected_fw_version );
  os_cpe     += ':' + detected_fw_version;
  os_version  = detected_fw_version;
}

if( detected_model != "unknown" ) {
  set_kb_item( name:"palo_alto_pan_os/model", value:detected_model );
  hw_app += " " + detected_model;
  hw_cpe += ":" + tolower( detected_model );
} else {
  hw_app += " Unknown Model";
  hw_cpe += ":unknown_model";
}

if( detected_fw_hotfix != "unknown" && detected_fw_version != "unknown" ) {
  set_kb_item( name:"palo_alto_pan_os/hotfix", value:detected_fw_hotfix );
  os_cpe     += '-h' + detected_fw_hotfix;
  os_version  = detected_fw_version + " Hotfix " + detected_fw_hotfix;
}

if( os_version ) {
  os_register_and_report( os:"Palo Alto PAN-OS " + os_version, cpe:os_cpe, desc:"Palo Alto PAN-OS Detection Consolidation", runs_key:"unixoide" );
} else {
  os_register_and_report( os:"Palo Alto PAN-OS", cpe:os_cpe, desc:"Palo Alto PAN-OS Detection Consolidation", runs_key:"unixoide" );
}

if( http_ports = get_kb_list( "palo_alto/http/port" ) ) {
  foreach port( http_ports ) {
    concluded = get_kb_item( "palo_alto/http/" + port + "/concluded" );
    concluded_url = get_kb_item( "palo_alto/http/" + port + "/concludedUrl" );
    extra += "HTTP(s) on port " + port + '/tcp\n';
    if( concluded )
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';
    if( concluded_url )
      extra += '  Concluded from version/product identification location: ' + concluded_url + '\n';

    # nb: Its expected to have this in here as the XML-API NVT is using
    # "palo_alto/ihttp/port" and will log all failed reasons to the key below
    failed = get_kb_item( "palo_alto/xml-api/" + port + "/fail_reason" );
    if( failed )
      failed_reasons += failed + '\n';

    register_product( cpe:hw_cpe, location:location, port:port, service:"www" );
    register_product( cpe:os_cpe, location:location, port:port, service:"www" );
  }
}

if( xml_api_ports = get_kb_list( "palo_alto/xml-api/port" ) ) {
  foreach port( xml_api_ports ) {
    concluded = get_kb_item( "palo_alto/xml-api/" + port + "/concluded" );
    concluded_url = get_kb_item( "palo_alto/xml-api/" + port + "/concludedUrl" );
    extra += "HTTP(s) (XML-API) on port " + port + '/tcp\n';

    if( concluded )
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';
    if( concluded_url )
      extra += '  Concluded from version/product identification location: ' + concluded_url + '\n';

    register_product( cpe:hw_cpe, location:location, port:port, service:"xml-api" );
    register_product( cpe:os_cpe, location:location, port:port, service:"xml-api" );
  }
}

if( snmp_ports = get_kb_list( "palo_alto/snmp/port" ) ) {
  foreach port( snmp_ports ) {
    extra += 'SNMP on port ' + port + '/udp\n';

    concluded = get_kb_item( "palo_alto/snmp/" + port + "/concluded" );
    if( concluded )
      extra += concluded + '\n';

    register_product( cpe:hw_cpe, location:location, port:port, service:"snmp", proto:"udp" );
    register_product( cpe:os_cpe, location:location, port:port, service:"snmp", proto:"udp" );
  }
}

if( ssh_ports = get_kb_list( "palo_alto/ssh-login/port" ) ) {
  foreach port( ssh_ports ) {
    extra += "SSH login on port " + port + '/tcp\n';
    concluded = get_kb_item( "palo_alto/ssh-login/" + port + "/concluded" );
    if( concluded )
      extra += '  Concluded from version/product identification result (Command: "show system info"): ' +
               concluded + '\n';

    register_product( cpe:hw_cpe, location:location, port:port, service:"ssh-login" );
    register_product( cpe:os_cpe, location:location, port:port, service:"ssh-login" );
  }
}

report = build_detection_report( app:os_app,
                                 version:os_version,
                                 install:location,
                                 cpe:os_cpe );

report += '\n\n' + build_detection_report( app:hw_app,
                                           skip_version:TRUE,
                                           install:location,
                                           cpe:hw_cpe );

if( extra ) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

if( failed_reasons ) {
  report += '\n\nXML-API credentials where provided via "Palo Alto Device Detection (XML-API)" ';
  report += '(OID:1.3.6.1.4.1.25623.1.0.105262) but the login at the XML-API failed for the following reasons:\n';
  report += '\n' + failed_reasons;
}

log_message( port:0, data:report );

exit( 0 );
