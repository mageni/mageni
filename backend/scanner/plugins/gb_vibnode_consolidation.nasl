###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vibnode_consolidation.nasl 10908 2018-08-10 15:00:08Z cfischer $
#
# PRUFTECHNIK VIBNODE Detection Consolidation
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.108338");
  script_version("$Revision: 10908 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:00:08 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-02-15 16:10:41 +0100 (Thu, 15 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PRUFTECHNIK VIBNODE Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_vibnode_telnet_detect.nasl", "gb_vibnode_http_detect.nasl", "gb_vibnode_ftp_detect.nasl");
  script_mandatory_keys("vibnode/detected");

  script_xref(name:"URL", value:"https://www.pruftechnik.com/products/condition-monitoring-systems/online-condition-monitoring-systems/discontinued-products-online-cm/vibnode.html");

  script_tag(name:"summary", value:"The script reports a detected PRUFTECHNIK VIBNODE device including the
  version number and exposed services.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

if( ! get_kb_item( "vibnode/detected" ) ) exit( 0 );

detected_app_version = "unknown";
detected_os_version  = "unknown";

foreach source( make_list( "telnet", "http", "ftp" ) ) {

  app_version_list = get_kb_list( "vibnode/" + source + "/*/app_version" );
  foreach app_version( app_version_list ) {
    if( app_version != "unknown" && detected_app_version == "unknown" ) {
      detected_app_version = app_version;
      set_kb_item( name:"vibnode/app_version", value:app_version );
    }
  }

  os_version_list = get_kb_list( "vibnode/" + source + "/*/os_version" );
  foreach os_version( os_version_list ) {
    if( os_version != "unknown" && detected_os_version == "unknown" ) {
      detected_os_version = os_version;
      set_kb_item( name:"vibnode/os_version", value:os_version );
    }
  }
}

if( detected_app_version != "unknown" ) {
  app_cpe = "cpe:/a:pruftechnik:vibnode:" + detected_app_version;
} else {
  app_cpe = "cpe:/a:pruftechnik:vibnode";
}

if( detected_os_version != "unknown" ) {
  os_cpe  = "cpe:/o:pruftechnik:vibnode_os:" + detected_os_version;
  os_name = "PRUFTECHNIK VIBNODE OS " + detected_os_version;
} else {
  os_cpe  = "cpe:/o:pruftechnik:vibnode_os";
  os_name = "PRUFTECHNIK VIBNODE OS";
}

register_and_report_os( os:os_name, cpe:os_cpe, desc:"PRUFTECHNIK VIBNODE Detection Consolidation", runs_key:"unixoide" );

location = "/";

if( telnet_port = get_kb_list( "vibnode/telnet/port" ) ) {
  foreach port( telnet_port ) {
    concluded  = get_kb_item( "vibnode/telnet/" + port + "/concluded" );
    extra     += '\nTelnet on port ' + port + '/tcp\n';
    if( concluded ) {
      extra += 'Concluded: ' + concluded + '\n';
    }
    register_product( cpe:app_cpe, location:location, port:port, service:"telnet" );
    register_product( cpe:os_cpe, location:location, port:port, service:"telnet" );
  }
}

if( http_port = get_kb_list( "vibnode/http/port" ) ) {
  foreach port( http_port ) {
    concluded  = get_kb_item( "vibnode/http/" + port + "/concluded" );
    extra     += '\nHTTP(s) on port ' + port + '/tcp\n';
    if( concluded ) {
      extra += 'Concluded: ' + concluded + '\n';
    }
    register_product( cpe:app_cpe, location:location, port:port, service:"www" );
    register_product( cpe:os_cpe, location:location, port:port, service:"www" );
  }
}

if( ftp_port = get_kb_list( "vibnode/ftp/port" ) ) {
  foreach port( ftp_port ) {
    concluded  = get_kb_item( "vibnode/ftp/" + port + "/concluded" );
    extra     += '\nFTP on port ' + port + '/tcp\n';
    if( concluded ) {
      extra += 'Concluded: ' + concluded + '\n';
    }
    register_product( cpe:app_cpe, location:location, port:port, service:"ftp" );
    register_product( cpe:os_cpe, location:location, port:port, service:"ftp" );
  }
}

report  = build_detection_report( app:"PRUFTECHNIK VIBNODE",
                                  version:detected_app_version,
                                  install:location,
                                  cpe:app_cpe );
report += '\n\n';
report += build_detection_report( app:"PRUFTECHNIK VIBNODE OS",
                                 version:detected_os_version,
                                 install:location,
                                 cpe:os_cpe );

if( extra ) {
  report += '\n\nDetection methods:\n';
  report += extra;
}

log_message( port:0, data:report );

exit( 0 );
