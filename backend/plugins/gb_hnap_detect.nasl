###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hnap_detect.nasl 12434 2018-11-20 11:03:44Z cfischer $
#
# Home Network Administration Protocol (HNAP) Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103908");
  script_version("$Revision: 12434 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 12:03:44 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-02-18 11:22:35 +0100 (Tue, 18 Feb 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Home Network Administration Protocol (HNAP) Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
  to determine if the Home Network Administration Protocol (HNAP) is supported.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:8080 );

url = "/HNAP1";
req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

# nb: e.g. on a D-Link DIR-868L the URL needs a trailing "/"
if( ! buf || "soap:Envelope" >!< buf || "SOAPActions" >!< buf || "http://purenetworks.com/HNAP1" >!< buf ) {
  url = "/HNAP1/";
  req = http_get( item:url, port:port );
  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );
}

if( buf && "soap:Envelope" >< buf && "SOAPActions" >< buf && "http://purenetworks.com/HNAP1" >< buf ) {

  # e.g. <VendorName>D-Link</VendorName>
  if( "<VendorName>" >< buf ) {
    vendor = eregmatch( pattern:"<VendorName>([^<]+)</VendorName>", string:buf );
    if( ! isnull( vendor[1] ) ) {
      set_kb_item( name:"HNAP/" + port + "/vendor", value:vendor[1] );
      set_kb_item( name:"HNAP/" + port + "/vendor_concluded", value:vendor[0] );
      set_kb_item( name:"HNAP/vendor", value:TRUE );
      report += '\nVendor:   ' + vendor[1];
    }
  }

  # e.g. <ModelName>DIR-868L</ModelName>
  if( "<ModelName>" >< buf ) {
    model = eregmatch( pattern:"<ModelName>([^<]+)</ModelName>", string:buf );
    if( ! isnull( model[1] ) ) {
      set_kb_item( name:"HNAP/" + port + "/model", value:model[1] );
      set_kb_item( name:"HNAP/" + port + "/model_concluded", value:model[0] );
      set_kb_item( name:"HNAP/model", value:TRUE );
      report += '\nModel:    ' + model[1];
    }
  }

  # e.g. <FirmwareVersion>2.03</FirmwareVersion>
  if( "<FirmwareVersion>" >< buf ) {
    fw = eregmatch( pattern:"<FirmwareVersion>([^<]+)</FirmwareVersion>", string:buf );
    if( ! isnull( fw[1] ) ) {
      set_kb_item( name:"HNAP/" + port + "/firmware", value:fw[1] );
      set_kb_item( name:"HNAP/" + port + "/firmware_concluded", value:fw[0] );
      set_kb_item( name:"HNAP/firmware", value:TRUE );
      report += '\nFirmware: ' + fw[1];
    }
  }

  # e.g. <HardwareVersion>B1</HardwareVersion>
  if( "<HardwareVersion>" >< buf ) {
    hw = eregmatch( pattern:"<HardwareVersion>([^<]+)</HardwareVersion>", string:buf );
    if( ! isnull( hw[1] ) ) {
      set_kb_item( name:"HNAP/" + port + "/hardware", value:hw[1] );
      set_kb_item( name:"HNAP/" + port + "/hardware_concluded", value:hw[0] );
      set_kb_item( name:"HNAP/hardware", value:TRUE );
      report += '\nHardware: ' + hw[1];
    }
  }

  conclUrl = report_vuln_url( url:url, port:port, url_only:TRUE );

  set_kb_item( name:"HNAP/port", value:port );
  set_kb_item( name:"HNAP/" + port + "/detected", value:TRUE );
  set_kb_item( name:"HNAP/" + port + "/conclurl", value:conclUrl );

  _report  = 'The remote host supports the Home Network Administration Protocol (HNAP).\n\n';
  _report += 'Discovery-URL: ' + conclUrl;
  if( strlen( report ) > 0 )
    _report += '\n\nExtracted Device information:\n' + report;

  log_message( data:_report, port:port );
}

exit( 0 );