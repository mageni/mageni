###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_axon_virtual_pbx_web_detect.nasl 11629 2018-09-26 17:02:49Z cfischer $
#
# Axon Virtual PBX Version Detection (HTTP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108033");
  script_version("$Revision: 11629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-26 19:02:49 +0200 (Wed, 26 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-01-02 10:00:00 +0100 (Mon, 02 Jan 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Axon Virtual PBX  Version Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 81);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Axon Virtual PBX.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:81 );

res = http_get_cache( item:"/", port:port );

if( "title>Axon - Login" >< res || "Main Page'>Axon</td>" >< res || "target=_blank>www.nch.com.au</a>" >< res ) {

  version = "unknown";

  ver = eregmatch( pattern:"v&.+([0-9]\.[0-9]+)", string:res );

  if( ! isnull( ver[1] ) ) version = ver[1];

  set_kb_item( name:"Axon-Virtual-PBX/installed", value:TRUE );
  set_kb_item( name:"Axon-Virtual-PBX/www/" + port + "/ver", value:version );
  set_kb_item( name:"Axon-Virtual-PBX/www/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:nch:axon_virtual_pbx:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:nch:axon_virtual_pbx';

  location = "/";

  register_product( cpe:cpe, port:port, location:location, service:"www" );
  log_message( data:build_detection_report( app:"Axon Virtual PBX",
                                            version:version,
                                            install:location,
                                            cpe:cpe,
                                            concluded:ver[0] ),
                                            port:port );
}

exit( 0 );
