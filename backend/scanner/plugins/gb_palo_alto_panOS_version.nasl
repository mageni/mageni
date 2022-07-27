###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_palo_alto_panOS_version.nasl 8743 2018-02-09 13:10:26Z cfischer $
#
# Palo Alto PAN-OS Version Detection Consolidation
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105263");
  script_version("$Revision: 8743 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-09 14:10:26 +0100 (Fri, 09 Feb 2018) $");
  script_tag(name:"creation_date", value:"2015-04-22 14:02:11 +0200 (Wed, 22 Apr 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Palo Alto PAN-OS Version Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl", "gb_palo_alto_version_api.nasl");
  script_mandatory_keys("palo_alto/detected");

  script_tag(name:"summary", value:"This script detect the PAN-OS Version through SSH or XML-API");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");

if( ! system = get_kb_item( "palo_alto/detected" ) ) exit( 0 );

detected_fw_version = "unknown";
detected_fw_hotfix  = "unknown";
detected_model      = "unknown";

foreach source( make_list( "ssh", "xml-api", "webui" ) ) {

  if( source == "ssh" ) {
    vpattern = 'sw-version: ([^ \r\n]+)';
    mpattern = 'model: ([^ \r\n]+)';
  } else if( source == "xml-api" ) {
    vpattern = '<sw-version>([^<]+)</sw-version>';
    mpattern = '<model>([^<]+)</model>';
  } else {
    continue;
  }

  system_list = get_kb_list( "palo_alto/" + source + "/*/system" );
  foreach system( system_list ) {

    version = eregmatch( pattern:vpattern, string:system );
    if( ! isnull( version[1] ) && detected_fw_version == "unknown" ) {
      detected_fw_version = version[1];
      if( "-h" >< detected_fw_version ) {
        version_and_hotfix  = split( detected_fw_version, sep:"-h", keep:FALSE );
        detected_fw_version = version_and_hotfix[0];
        detected_fw_hotfix  = version_and_hotfix[1];
      }
    }

    model = eregmatch( pattern:mpattern, string:system );
    if( ! isnull( model[1] ) && detected_model == "unknown" ) {
      detected_model = model[1];
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
  register_and_report_os( os:"Palo Alto PAN-OS " + os_version, cpe:os_cpe, desc:"Palo Alto PAN-OS Version Detection Consolidation", runs_key:"unixoide" );
} else {
  register_and_report_os( os:"Palo Alto PAN-OS", cpe:os_cpe, desc:"Palo Alto PAN-OS Version Detection Consolidation", runs_key:"unixoide" );
}

location = "/";

if( webui_ports = get_kb_list( "palo_alto/webui/port" ) ) {
  foreach port( webui_ports ) {
    concluded = get_kb_item( "palo_alto/webui/" + port + "/concluded" );
    extra += "HTTP(s) on port " + port + '/tcp\n';
    if( concluded ) {
      extra += 'Concluded from: ' + concluded + '\n';
    }
    # nb: Its expected to have this in here as the XML-API NVT is using
    # "palo_alto/webui/port" and will log all failed reasons to the key below
    failed = get_kb_item( "palo_alto/xml-api/" + port + "/fail_reason" );
    if( failed ) {
      failed_reasons += failed + '\n';
    }
    register_product( cpe:hw_cpe, location:location, port:port, service:"www" );
    register_product( cpe:os_cpe, location:location, port:port, service:"www" );
  }
}

if( xml_api_ports = get_kb_list( "palo_alto/xml-api/port" ) ) {
  foreach port( xml_api_ports ) {
    concluded = get_kb_item( "palo_alto/xml-api/" + port + "/concluded" );
    extra += "HTTP(s) on port " + port + '/tcp\n';
    if( concluded ) {
      extra += 'Concluded from: ' + concluded + '\n';
    }
    register_product( cpe:hw_cpe, location:location, port:port, service:"xml-api" );
    register_product( cpe:os_cpe, location:location, port:port, service:"xml-api" );
  }
}

if( ssh_ports = get_kb_list( "palo_alto/ssh/port" ) ) {
  foreach port( ssh_ports ) {
    extra += "SSH Login on port " + port + '/tcp\n';
    register_product( cpe:hw_cpe, location:location, port:port, service:"ssh" );
    register_product( cpe:os_cpe, location:location, port:port, service:"ssh" );
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
  report += '\n\nXML-API credentials where provided via "Palo Alto PAN-OS Version Detection (XML-API)" ';
  report += '(OID:1.3.6.1.4.1.25623.1.0.105262) but the login at the XML-API failed for the following reasons:\n';
  report += '\n' + failed_reasons;
}

log_message( port:0, data:report );

exit( 0 );
