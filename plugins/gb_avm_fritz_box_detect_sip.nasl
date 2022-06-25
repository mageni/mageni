###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avm_fritz_box_detect_sip.nasl 13734 2019-02-18 11:03:47Z cfischer $
#
# AVM FRITZ!Box Detection (SIP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108037");
  script_version("$Revision: 13734 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 12:03:47 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-01-05 13:21:05 +0100 (Thu, 05 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("AVM FRITZ!Box Detection (SIP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("sip_detection.nasl");
  script_mandatory_keys("sip/banner/available");

  script_tag(name:"summary", value:"The script attempts to identify an AVM FRITZ!Box via SIP
  banner and tries to extract the model and version number.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("sip.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos['port'];
proto = infos['proto'];

banner = sip_get_banner( port:port, proto:proto );

if( banner && ( "AVM FRITZ" >< banner || "FRITZ!OS" >< banner ) ) {

  set_kb_item( name:"avm_fritz_box/detected", value:TRUE );
  set_kb_item( name:"avm_fritz_box/sip/" + proto + "/detected", value:TRUE );
  set_kb_item( name:"avm_fritz_box/sip/" + proto + "/port", value:port );
  set_kb_item( name:"avm_fritz_box/sip/" + proto + "/" + port + "/concluded", value:banner );

  type = "unknown";
  model = "unknown";
  fw_version = "unknown";

  # User-Agent: AVM FRITZ!Box Fon WLAN 7170 29.04.76 (Jul 13 2009)
  # User-Agent: AVM FRITZ!Box Fon WLAN 7141 (UI) 40.04.77 TAL (Feb 10 2014)
  # User-Agent: AVM FRITZ!Box 6810 LTE 108.05.56 (Aug 13 2013)
  mo = eregmatch( pattern:'AVM FRITZ!Box (Fon WLAN|WLAN)? ?([0-9]+( (v[0-9]+|vDSL|SL|LTE|Cable))?)', string:banner );
  if( ! isnull( mo[1] ) ) type = mo[1];
  if( ! isnull( mo[2] ) ) model = mo[2];

  fw = eregmatch( pattern:'AVM FRITZ!Box .* ([0-9]+\\.[0-9]+\\.[0-9]+)($| |\\()', string:banner );
  if( ! isnull( fw[1] ) ) fw_version = fw[1];

  set_kb_item( name:"avm_fritz_box/sip/" + proto + "/" + port + "/type", value:type );
  set_kb_item( name:"avm_fritz_box/sip/" + proto + "/" + port + "/model", value:model );
  set_kb_item( name:"avm_fritz_box/sip/" + proto + "/" + port + "/firmware_version", value:fw_version );
}

exit( 0 );