###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_reservo_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Reservo Image Hosting Detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113094");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-26 12:39:40 +0100 (Fri, 26 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Reservo Image Hosting Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Product detection for Reservo Image Hosting Server.");

  script_xref(name:"URL", value:"https://reservo.co/");

  exit(0);
}

CPE = "cpe:/a:reservo:image_hosting";

include( "http_func.inc" );
include( "host_details.inc" );
include( "http_keepalive.inc" );

install = "/";
port = get_http_port( default: 80 );

buf = http_get_cache( item: install, port: port );

if( "themes/reservo/frontend" >< buf ) {
  set_kb_item( name: "reservo/installed", value: TRUE );

  register_product( cpe: CPE, location: install, port: port);
  log_message( data:build_detection_report( app:"Reservo Image Hosting",
                                            install: install,
                                            cpe: CPE ),
                                            port: port);
}

exit( 0 );
