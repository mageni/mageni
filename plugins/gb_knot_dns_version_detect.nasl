###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_knot_dns_version_detect.nasl 4450 2016-11-09 08:12:58Z cfi $
#
# KNOT DNS Server Version Detection
#
# Authors:
# kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806810");
  script_version("$Revision: 4450 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-11-09 09:12:58 +0100 (Wed, 09 Nov 2016) $");
  script_tag(name:"creation_date", value:"2016-01-04 13:14:29 +0530 (Mon, 04 Jan 2016)");
  script_name("KNOT DNS Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "dns_server.nasl");
  script_mandatory_keys("DNS/identified");

  script_tag(name:"summary", value:"Detection of installed version
  of Knot DNS Server.

  This script sends standard query and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("misc_func.inc");
include("host_details.inc");

function getVersion(data, port, proto) {

  local_var data, port, proto, version, ver, cpe;

  if( "knot dns" >!< tolower( data ) ) return;

  version = "unknown";
  ver = eregmatch( pattern:"Knot DNS ([0-9A-Z.-]+)", string:data, icase:TRUE );
  if( ver[1] ) version = ver[1];

  cpe = build_cpe( value:version, exp:"^([0-9/.]+)", base:"cpe:/a:knot:dns:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:knot:dns";

  set_kb_item( name:"KnotDNS/version", value:version );
  set_kb_item( name:"KnotDNS/installed", value:TRUE );

  register_product( cpe:cpe, location:port + "/" + proto, port:port, proto:proto );
  log_message( data:build_detection_report( app:"KNOT DNS",
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
