###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libupnp_detect.nasl 10911 2018-08-10 15:16:34Z cfischer $
#
# libupnp Detection (TCP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106376");
  script_version("$Revision: 10911 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:16:34 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-11-04 14:37:33 +0700 (Fri, 04 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("libupnp Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 49152);
  script_mandatory_keys("sdk_for_upnp/banner");

  script_xref(name:"URL", value:"https://sourceforge.net/projects/pupnp/");

  script_tag(name:"summary", value:"Detection of libupnp

  The script sends a connection request to the server and attempts to detect the presence of libupnp and to
  extract its version");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");


port = get_http_port( default:49152 );
banner = get_http_banner( port:port );

if( banner && "sdk for upnp" >< tolower( banner ) ) {

  version = "unknown";

  vers = eregmatch( pattern:"(Portable|Intel|WindRiver) SDK for UPnP devices/([0-9.]+)", string:banner, icase:TRUE );
  if( ! isnull( vers[2] ) ) version = vers[2];

  set_kb_item( name:"libupnp/" + port + "/version", value:version );
  set_kb_item( name:"libupnp/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:libupnp_project:libupnp:" );
  if( ! cpe )
    cpe = 'cpe:/a:libupnp_project:libupnp';

  register_product( cpe:cpe, location:"/", port:port, proto:"tcp", service:"www" );

  log_message( data:build_detection_report( app:"libupnp",
                                            version:version,
                                            install:"/",
                                            cpe:cpe,
                                            concluded:vers[0] ),
                                            proto:"tcp",
                                            port:port );
}

exit( 0 );
