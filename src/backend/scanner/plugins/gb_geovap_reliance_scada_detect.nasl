###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_geovap_reliance_scada_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Geovap Reliance SCADA Detection
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.112149");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-06 15:47:24 +0100 (Wed, 06 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Geovap Reliance SCADA Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This scripts sends an HTTP GET request to figure out whether a Geovap Reliance SCADA system is installed on the target host, and, if so, which version.");

  script_xref(name:"URL", value:"https://www.reliance-scada.com");

  exit(0);
}

include( "cpe.inc" );
include( "host_details.inc" );
include( "http_func.inc" );


port = get_http_port( default: 80 );
foreach dir ( make_list_unique( "/", cgi_dirs( port: port ) ) ) {
  redir = "/?q=0&l=0";

  if( dir == "/" ) url = redir;
  else url = dir + redir;

  req = http_get( port: port, item: url );
  resp = http_send_recv( data: req, port: port );

  if( resp =~ 'Reliance 4 Control Server' && resp =~ 'http(s)?://www.reliance-scada.com' ) {
    set_kb_item( name: "geovap/reliance-scada/detected", value: TRUE );

    version = "unknown";
    version_match = eregmatch( pattern: 'target="_blank">Reliance</a> ([0-9.]+)(,)?.(Update.([0-9])|.*).\\|', string: resp );

    if ( version_match[1] && version_match[4] ) {
      version = version_match[1] + " Update " + version_match[4];
    } else if ( version_match[1] ) {
        version = version_match[1];
    } else {
      version_match = eregmatch( pattern: '<td>Version</td><td>([0-9.]+) ', string: resp );
      if ( version_match[1] ) version = version_match[1];
    }

    # Version output from 'build_cpe()' sets versions like '4.7.3 Update 1' to '4.7.31' so we set a kb_item in order to avoid false positives
    if ( version && version != "unknown" ) {
      set_kb_item( name: "geovap/reliance-scada/version", value: version );
    }

    # nb: versions like '4.7.3 Update 1'
    if ( version_match[4] )
      exp = "^([0-9.]+).*([0-9])";
    # nb: versions like '4.6.3.22616'
    else
      exp = "^([0-9.]+)";

    register_and_report_cpe( app: "Geovap Reliance SCADA", ver: version, concluded: version_match[0], base: "cpe:/a:geovap:reliance-scada:", expr: exp, insloc: dir, regPort: port, extra: version_match[3] );
    exit( 0 );
  }
}
