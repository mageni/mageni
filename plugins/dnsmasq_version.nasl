###############################################################################
# OpenVAS Vulnerability Test
# $Id: dnsmasq_version.nasl 10931 2018-08-11 13:51:20Z cfischer $
#
# Dnsmasq Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100266");
  script_version("$Revision: 10931 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-11 15:51:20 +0200 (Sat, 11 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-09-01 22:29:29 +0200 (Tue, 01 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Dnsmasq Detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_dependencies("find_service.nasl", "dns_server.nasl");
  script_mandatory_keys("DNS/identified");

  script_tag(name:"summary", value:"Detection of Dnsmasq");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

function getVersion( data, port, proto ) {

  local_var data, port, proto, version, ver, cpe;

  if( "dnsmasq" >!< tolower( data ) ) return;

  version = "unknown";
  # dnsmasq-pi-hole-2.79
  # dnsmasq-2.76
  ver = eregmatch( pattern:"dnsmasq-(pi-hole-)?([0-9.]+)", string:data, icase:TRUE );
  if( ver[2] ) version = ver[2];

  set_kb_item( name:"dnsmasq/version", value:version );
  set_kb_item( name:"dnsmasq/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:thekelleys:dnsmasq:" );
  if( ! cpe )
    cpe = "cpe:/a:thekelleys:dnsmasq";

  register_product( cpe:cpe, location:port + "/" + proto, port:port, proto:proto );
  log_message( data:build_detection_report( app:"Dnsmasq",
                                            version:version,
                                            install:port + "/" + proto,
                                            cpe:cpe,
                                            concluded:data ),
                                            port:port,
                                            proto:proto );
}

udp_Ports = get_kb_list( "DNS/udp/version_request" );
foreach port( udp_Ports ) {
  data = get_kb_item( "DNS/udp/version_request/" + port );
  if( ! data ) continue;
  getVersion( data:data, port:port, proto:"udp" );
}

tcp_Ports = get_kb_list( "DNS/tcp/version_request" );
foreach port( tcp_Ports ) {
  data = get_kb_item( "DNS/tcp/version_request/" + port );
  if( ! data ) continue;
  getVersion( data:data, port:port, proto:"tcp" );
}

exit( 0 );
