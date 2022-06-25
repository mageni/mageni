# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100266");
  script_version("2021-03-26T10:02:15+0000");
  script_tag(name:"last_modification", value:"2021-03-29 10:41:25 +0000 (Mon, 29 Mar 2021)");
  script_tag(name:"creation_date", value:"2009-09-01 22:29:29 +0200 (Tue, 01 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Dnsmasq Detection (DNS)");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_dependencies("find_service.nasl", "dns_server.nasl");
  script_mandatory_keys("DNS/identified");

  script_tag(name:"summary", value:"DNS based detection of Dnsmasq.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

function getVersion( data, port, proto ) {

  local_var data, port, proto;
  local_var version, ver;

  if( ! data || "dnsmasq" >!< tolower( data ) )
    return;

  version = "unknown";

  # dnsmasq-pi-hole-2.79
  # dnsmasq-2.76
  ver = eregmatch( pattern:"dnsmasq-(pi-hole-)?([0-9.]+)", string:data, icase:TRUE );
  if( ver[2] )
    version = ver[2];

  set_kb_item( name:"thekelleys/dnsmasq/detected", value:TRUE );
  set_kb_item( name:"thekelleys/dnsmasq/dns-" + proto + "/detected", value:TRUE );
  set_kb_item( name:"thekelleys/dnsmasq/dns-" + proto + "/" + port + "/installs", value:port + "#---#" + port + "/" + proto + "#---#" + version + "#---#" + data );
}

udp_ports = get_kb_list( "DNS/udp/version_request" );
foreach port( udp_ports ) {

  data = get_kb_item( "DNS/udp/version_request/" + port );
  if( ! data )
    continue;

  getVersion( data:data, port:port, proto:"udp" );
}

tcp_ports = get_kb_list( "DNS/tcp/version_request" );
foreach port( tcp_ports ) {

  data = get_kb_item( "DNS/tcp/version_request/" + port );
  if( ! data )
    continue;

  getVersion( data:data, port:port, proto:"tcp" );
}

exit( 0 );