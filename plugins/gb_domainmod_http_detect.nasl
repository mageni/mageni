###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_domainmod_http_detect.nasl 13242 2019-01-23 12:36:13Z jschulte $
#
# DomainMOD Detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.113326");
  script_version("$Revision: 13242 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-23 13:36:13 +0100 (Wed, 23 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-22 14:43:33 +0100 (Tue, 22 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("DomainMOD Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Checks whether DomainMOD is present on
  the target system and if so, tries to figure out the installed version.");

  script_xref(name:"URL", value:"https://domainmod.org/");
  script_xref(name:"URL", value:"https://github.com/domainmod");

  exit(0);
}

CPE = "cpe:/a:domainmod:domainmod:";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc" );

port = get_http_port( default: 80 );

foreach location( make_list_unique( "/", "/domainmod", cgi_dirs( port: port ) ) ) {
  dir = location;
  if( dir == "/" )
    dir = "";

  url = dir += "/CHANGELOG";
  buf = http_get_cache( item: url, port: port );
  if( buf !~ 'DomainMod CHANGELOG' ) continue;

  set_kb_item( name: "domainmod/detected", value: TRUE );

  version = "unknown";

  ver = eregmatch( string: buf, pattern: 'v([0-9.]+)' );
  if( ! isnull( ver[1] ) ) {
    version = ver[1];
  }

  register_and_report_cpe( app: 'DomainMOD',
                           ver: version,
                           concluded: ver[0],
                           base: CPE,
                           expr: '([0-9.]+)',
                           insloc: location,
                           regPort: port,
                           conclUrl: url );

  exit( 0 );
}

exit( 0 );
