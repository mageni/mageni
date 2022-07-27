# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108707");
  script_version("2020-01-31T11:19:02+0000");
  script_tag(name:"last_modification", value:"2020-01-31 11:19:02 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-31 09:47:18 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("LANCOM Device Detection (SIP)");

  script_tag(name:"summary", value:"Detection of LANCOM devices.

  This script performs SIP based detection of LANCOM devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("sip_detection.nasl");
  script_mandatory_keys("sip/banner/available");

  exit(0);
}

include("sip.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos["port"];
proto = infos["proto"];

banner = get_kb_item( "sip/useragent_banner/" + proto + "/" + port );
if( ! banner )
  exit( 0 );

# User-Agent: LANCOM 1781A / 9.10.0333 / 14.07.2015
# User-Agent: LANCOM 1722 VoIP (Annex B) / 8.84.0289 / 21.12.2015
# User-Agent: LANCOM 1631E / 9.10.0426 / 22.10.2015
# User-Agent: LANCOM 1781A-4G / 9.10.0426 / 22.10.2015
# User-Agent: LANCOM 1781VAW (over ISDN) / 9.10.0426 / 22.10.2015
# User-Agent: LANCOM 884 VoIP (over ISDN) / 10.20.0455 / 29.04.2019
#
# nb: Some have also "Server: Lancom" but that seems to be user-configurable.
# nb: useragent_banner KB entry doesn't include the "User-Agent:" prefix.

if( "LANCOM " >< banner ) {

  set_kb_item( name:"lancom/detected", value:TRUE );
  set_kb_item( name:"lancom/sip/" + proto + "/detected", value:TRUE );
  set_kb_item( name:"lancom/sip/" + proto + "/port", value:port );
  set_kb_item( name:"lancom/sip/" + proto + "/" + port + "/detected", value:TRUE );

  version = "unknown";
  model = "unknown";

  infos = eregmatch( pattern:"LANCOM ([^ ]+)([A-Za-z0-9()/ +-]+|[A-Za-z0-9()/ +-.]+\))? ([0-9]+\.[0-9.]+)", string:banner );
  if( ! isnull( infos[1] ) )
    model = infos[1];

  if( ! isnull( infos[3] ) )
    version = infos[3];

  set_kb_item( name:"lancom/sip/" + proto + "/" + port + "/model", value:model );
  set_kb_item( name:"lancom/sip/" + proto + "/" + port + "/version", value:version );
  if( infos[0] )
    set_kb_item( name:"lancom/sip/" + proto + "/" + port + "/concluded", value:infos[0] );
}

exit( 0 );
