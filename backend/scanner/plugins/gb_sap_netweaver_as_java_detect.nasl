###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sap_netweaver_as_java_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# SAP Netweaver Application Server AS Java Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.113267");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-09-13 13:37:00 +0200 (Thu, 13 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SAP Netweaver Application Server AS Java Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection for SAP Netweaver Application Server: AS Java.");

  script_xref(name:"URL", value:"https://wiki.scn.sap.com/wiki/display/ASJAVA/");

  exit(0);
}

CPE = "cpe:/a:sap:netweaver_as_java:";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc" );

port = get_http_port( default: 80 );

foreach location( make_list_unique( "/", cgi_dirs( port: port ) ) ) {
  dir = location;
  if( dir == "/" )
    dir = "";
  dir = dir + "/startpage";
  buf = http_get_cache( item: dir, port: port );
  if( buf =~ 'server: SAP NetWeaver Application Server [^/]*/ AS Java' ) {
    set_kb_item( name: "sap/netweaver_as_java/detected", value: TRUE );
    set_kb_item( name: "sap/netweaver_as_java/port", value: port );
    set_kb_item( name: "sap/netweaver_as_java/location", value: location );

    version = "unknown";

    ver = eregmatch( string: buf, pattern: 'server: SAP NetWeaver Application Server [^/]*/ AS Java ([0-9.]+)', icase: TRUE );
    if( ! isnull( ver[1] ) ) {
      version = ver[1];
      set_kb_item( name: "sap/netweaver_as_java/version", value: version );
    }

    register_and_report_cpe( app: "SAP Netweaver Application Server AS Java",
                             ver: version,
                             concluded: ver[0],
                             base: CPE,
                             expr: '([0-9.]+)',
                             insloc: location,
                             regPort: port,
                             conclUrl: dir );

    exit( 0 );
  }
}
