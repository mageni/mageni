###############################################################################
# OpenVAS Vulnerability Test
# $Id: bind_version.nasl 10945 2018-08-14 06:57:51Z santu $
# Description: Determine which version of BIND name daemon is running
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10028");
  script_version("$Revision: 10945 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-14 08:57:51 +0200 (Tue, 14 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Determine which version of BIND name daemon is running");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("Product detection");
  script_dependencies("dnsmasq_version.nasl", "pdns_version.nasl");
  script_mandatory_keys("DNS/identified");
  script_exclude_keys("dnsmasq/installed", "powerdns/recursor/installed", "powerdns/authoritative_server/installed"); # Don't detect dnsmasq or PowerDNS as BIND.

  # start report off with generic description ... lots of proprietary DNS servers (Cisco, QIP, a bunch more
  # are all BIND-based...
  script_tag(name:"summary", value:"BIND 'NAMED' is an open-source DNS server from ISC.org. Many proprietary
  DNS servers are based on BIND source code.");

  script_tag(name:"insight", value:"The BIND based NAMED servers (or DNS servers) allow  remote users
  to query for version and type information. The query of the CHAOS TXT record 'version.bind', will
  typically prompt the server to send the information back to the querying source.");

  script_tag(name:"solution", value:"Using the 'version' directive in the 'options' section will block
  the 'version.bind' query, but it will not log such attempts.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("misc_func.inc");
include("host_details.inc");

function getVersion( data, port, proto ) {

  local_var data, port, proto, version, ver, cpe;

  version = "unknown";

  if( "ISC BIND" >< data || "BIND" >< data ) {
    ver = eregmatch( pattern:'BIND ([0-9A-Za-z.-]+)', string:data );
  } else {
    ver = eregmatch( pattern:'([0-9A-Za-z.-]+)', string:data );
  }

  ## sometimes version comes with the ubuntu string
  if(ver[1] && (ver[1] =~ "(U|u)buntu")){
    ver = eregmatch( pattern:'([0-9A-Za-z.-]+).(U|u)buntu', string:ver[1] );
  }

  if( ver[1] ) version = ver[1];

  version = ereg_replace( string:version, pattern: "-", replace: "." );
  if( version !~ "^[0-9]") return;

  set_kb_item( name:"bind/version", value:version );
  set_kb_item( name:"ISC BIND/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"([0-9A-Za-z.-]+)", base:"cpe:/a:isc:bind:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:isc:bind";

  register_product( cpe:cpe, location:port + "/" + proto, port:port, proto:proto );
  log_message( data:build_detection_report( app:"Bind",
                                            version:version,
                                            install:port + "/" + proto,
                                            cpe:cpe,
                                            concluded:data ),
                                            port:port,
                                            proto:proto );
}

# Don't detect dnsmasq or PowerDNS as BIND.
if( get_kb_item( "dnsmasq/installed" ) ) exit( 0 );
if( get_kb_item( "powerdns/authoritative_server/installed" ) ) exit( 0 );
if( get_kb_item( "powerdns/recursor/installed" ) ) exit( 0 );

udp_Ports = get_kb_list("DNS/udp/version_request");
foreach port( udp_Ports ) {

  data = get_kb_item( "DNS/udp/version_request/" + port );
  if( ! data ) continue;

  # Don't detect dnsmasq or PowerDNS as BIND.
  if( "dnsmasq" >< tolower( data ) || "powerdns" >< tolower( data ) ) continue;

  getVersion( data:data, port:port, proto:"udp" );
}


tcp_Ports = get_kb_list( "DNS/tcp/version_request" );
foreach port( tcp_Ports ) {

  data = get_kb_item( "DNS/tcp/version_request/" + port );
  if( ! data ) continue;

  # Don't detect dnsmasq or PowerDNS as BIND.
  if( "dnsmasq" >< tolower( data ) || "powerdns" >< tolower( data ) ) continue;

  getVersion( data:data, port:port, proto:"tcp" );
}

exit( 0 );
