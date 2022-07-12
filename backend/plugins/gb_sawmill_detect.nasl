###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sawmill_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Sawmill Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.100867");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2010-10-22 14:10:21 +0200 (Fri, 22 Oct 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Sawmill Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8988);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running Sawmill, a hierarchical log analysis tool.");

  script_xref(name:"URL", value:"http://www.sawmill.net");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:8988 );

banner = get_http_banner( port:port );

buf = http_get_cache( item:"/", port:port );

if( ( ! banner || "erver: Sawmill" >!< banner ) && "<title>Sawmill" >!< buf && "/picts/sawmill_logo.png" >!< buf ) exit( 0 );

vers = "unknown";

version = eregmatch( string: banner, pattern: "Server: Sawmill/([0-9.]+)", icase:TRUE );

if( ! isnull( version[1] ) ) {
  vers = chomp( version[1] );
}

set_kb_item( name:"www/" + port + "/sawmill", value:vers );
set_kb_item( name:"sawmill/installed", value:TRUE );

cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:sawmill:sawmill:" );
if( isnull( cpe ) )
  cpe = 'cpe:/a:sawmill:sawmill';

register_product( cpe:cpe, location:port + '/tcp', port:port );

log_message( data: build_detection_report( app:"Sawmill",
                                           version:vers,
                                           install:port + '/tcp',
                                           cpe:cpe,
                                           concluded:version[0] ),
                                           port:port );

exit( 0 );
