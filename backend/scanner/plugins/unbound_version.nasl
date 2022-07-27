###############################################################################
# OpenVAS Vulnerability Test
# $Id: unbound_version.nasl 10898 2018-08-10 13:38:13Z cfischer $
#
# Unbound DNS resolver Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100417");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10898 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:38:13 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Unbound DNS resolver Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "dns_server.nasl");
  script_mandatory_keys("DNS/identified");

  script_tag(name:"solution", value:"Set 'hide-version: yes' in unbound.conf.");
  script_tag(name:"summary", value:"The Unbound DNS resolver is running at this host.
  Unbound is a validating, recursive, and caching DNS resolver.

  The Unbound DNS resolver allow remote users to query for version and type
  information. The query of the CHAOS TXT record 'version.bind', will
  typically prompt the server to send the information back to the
  querying source.");

  script_xref(name:"URL", value:"http://unbound.net");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("cpe.inc");

function getVersion( data, port, proto ) {

  local_var data, port, proto, version, ver, cpe;

  if( "unbound" >!< tolower( data ) ) return;

  version = "unknown";
  ver = eregmatch( pattern:"unbound ([0-9.]+)", string:data, icase:TRUE );
  if( ver[1] ) version = ver[1];

  set_kb_item( name:"unbound/version", value:version );
  set_kb_item( name:"unbound/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9/.]+)", base:"cpe:/a:unbound:unbound:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:unbound:unbound";

  register_product( cpe:cpe, location:port + "/" + proto, port:port, proto:proto );
  log_message( data:build_detection_report( app:"Unbound",
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
