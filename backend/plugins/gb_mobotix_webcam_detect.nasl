###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mobotix_webcam_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Mobotix Webcam Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113232");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-07-18 09:55:45 +0200 (Wed, 18 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Mobotix Webcam Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Mobotix Webcam devices.");

  script_xref(name:"URL", value:"https://www.mobotix.com");

  exit(0);
}

CPE = "cpe:/h:mobotix:webcam:";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc" );

port = get_http_port( default: 8080 );

buf = http_get_cache( port: port, item: "/" );

if( buf =~ 'content="MOBOTIX AG, Germany"' &&
  ( buf =~ '/control/camerainfo'  || buf =~ 'title=\'Show Camera info\'' ) ) {
  set_kb_item( name: "mobotix/webcam/detected", value: TRUE );
  set_kb_item( name: "mobotix/webcam/http_port", value: port );

  model = "unknown";
  mod = eregmatch( string: buf, pattern: '<b>MOBOTIX ([A-Za-z0-9]+)</b>' );
  if( ! isnull( mod[1] ) ) {
    model = mod[1];
  }
  set_kb_item( name: "mobotix/webcam/model", value: model );

  register_and_report_cpe( app: "Mobotix Webcam",
                           base: CPE,
                           expr: '([0-9]+)',
                           insloc: '/',
                           regPort: port );
}
exit( 0 );
