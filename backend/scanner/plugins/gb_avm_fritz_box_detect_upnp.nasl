###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avm_fritz_box_detect_upnp.nasl 11412 2018-09-16 10:21:40Z cfischer $
#
# AVM FRITZ!Box Detection (UPnP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108038");
  script_version("$Revision: 11412 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-16 12:21:40 +0200 (Sun, 16 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-01-05 13:21:05 +0100 (Thu, 05 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("AVM FRITZ!Box Detection (UPnP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_upnp_detect.nasl");
  script_mandatory_keys("upnp/identified");

  script_tag(name:"summary", value:"The script attempts to identify an AVM FRITZ!Box via UPnP
  banner and tries to extract the model and version number.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

port = get_kb_item( "Services/udp/upnp" );
if( ! port ) port = 1900;
if( ! get_udp_port_state( port ) ) exit( 0 );

banner = get_kb_item( "upnp/" + port + "/server" );
if( egrep( pattern:"SERVER: FRITZ!Box", string:banner, icase:TRUE ) ) {

  set_kb_item( name:"avm_fritz_box/detected", value:TRUE );
  set_kb_item( name:"avm_fritz_box/upnp/detected", value:TRUE );
  set_kb_item( name:"avm_fritz_box/upnp/port", value:port );
  replace_kb_item( name:"avm_fritz_box/upnp/" + port + "/concluded", value:banner );

  type = "unknown";
  model = "unknown";
  fw_version = "unknown";

  # SERVER: FRITZ!Box 7560 UPnP/1.0 AVM FRITZ!Box 7560 149.06.69
  # SERVER: FRITZ!Box 7490 (UI) UPnP/1.0 AVM FRITZ!Box 7490 (UI) 113.06.93
  # SERVER: FRITZ!Box Fon WLAN 7360 UPnP/1.0 AVM FRITZ!Box Fon WLAN 7360 124.06.83
  # SERVER: FRITZ!Box 5490 UPnP/1.0 AVM FRITZ!Box 5490 151.06.83
  # SERVER: FRITZ!Box Fon WLAN 7390 UPnP/1.0 AVM FRITZ!Box Fon WLAN 7390 84.06.83
  # SERVER: FRITZ!Box 7430 UPnP/1.0 AVM FRITZ!Box 7430 146.06.52
  # SERVER: FRITZ!Box 7330 UPnP/1.0 AVM FRITZ!Box 7330 107.06.54
  # SERVER: FRITZ!Box Fon Annex A UPnP/1.0 AVM FRITZ!Box Fon Annex A 06.04.49
  # SERVER: FRITZ!Box Fon WLAN 7270 v3 UPnP/1.0 AVM FRITZ!Box Fon WLAN 7270 v3 74.05.53
  mo = eregmatch( pattern:'AVM FRITZ!Box (Fon WLAN|WLAN)? ?([0-9]+( (v[0-9]+|vDSL|SL|LTE|Cable))?)', string:banner );
  if( ! isnull( mo[1] ) ) type = mo[1];
  if( ! isnull( mo[2] ) ) model = mo[2];

  fw = eregmatch( pattern:'AVM FRITZ!Box .* ([0-9]+\\.[0-9]+\\.[0-9]+)', string:banner );
  if( ! isnull( fw[1] ) ) fw_version = fw[1];

  set_kb_item( name:"avm_fritz_box/upnp/" + port + "/type", value:type );
  set_kb_item( name:"avm_fritz_box/upnp/" + port + "/model", value:model );
  set_kb_item( name:"avm_fritz_box/upnp/" + port + "/firmware_version", value:fw_version );
}

exit( 0 );