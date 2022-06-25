###############################################################################
# OpenVAS Vulnerability Test
# $Id: pdns_version.nasl 11365 2018-09-12 16:02:10Z asteins $
#
# PowerDNS (Authoritative Server and Recursor) Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.100432");
  script_version("$Revision: 11365 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 18:02:10 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-01-07 12:29:25 +0100 (Thu, 07 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PowerDNS (Authoritative Server and Recursor) Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "dns_server.nasl");
  script_mandatory_keys("DNS/identified");

  script_xref(name:"URL", value:"http://www.powerdns.com/");

  script_tag(name:"summary", value:"Detection of PowerDNS (Authoritative Server and Recursor)");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("cpe.inc");

function getVersion( data, port, proto ) {

  local_var data, port, proto, version, ver, cpe;

  if( "powerdns" >!< tolower( data ) ) return;

  version = "unknown";
  ver = eregmatch( pattern:"PowerDNS [a-zA-Z ]*([0-9.]+)", string:data, icase:TRUE );
  if( ver[1] ) version = ver[1];

  set_kb_item( name:"powerdns/recursor_or_authoritative_server/installed", value:TRUE );

  if( "Recursor" >< ver[0] ) {
    type = "Recursor";
    set_kb_item( name:"powerdns/recursor/installed", value:TRUE );
    set_kb_item( name:"powerdns/recursor/version", value:version );
    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:powerdns:recursor:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:powerdns:recursor";
  } else {
    type = "Authoritative Server";
    set_kb_item( name:"powerdns/authoritative_server/installed", value:TRUE );
    set_kb_item( name:"powerdns/authoritative_server/version", value:version );
    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:powerdns:authoritative_server:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:powerdns:authoritative_server";
  }

  register_product( cpe:cpe, location:port + "/" + proto, port:port, proto:proto );
  log_message( data:build_detection_report( app:"PowerDNS " + type,
                                            version:version,
                                            install:port + "/" + proto,
                                            cpe:cpe,
                                            concluded:ver[0] ),
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
