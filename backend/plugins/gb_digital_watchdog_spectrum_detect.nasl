###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_digital_watchdog_spectrum_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Digital Watchdog Spectrum Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.113237");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-07-25 12:00:00 +0200 (Wed, 25 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Digital Watchdog Spectrum Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 7001);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects Digital Watchdog Products.");
  script_tag(name:"insight", value:"All Digital Watchdog Products come with the 'Spectrum' software");

  script_xref(name:"URL", value:"https://digital-watchdog.com/");

  exit(0);
}

CPE = "cpe:/h:digital_watchdog:spectrum:";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc");

port = get_http_port( default: 7001 );

foreach dir ( make_list_unique( "/", cgi_dirs( port: port ) ) ) {
  location = dir;
  if( location == "/" )
    location = "";

  location = location + "/static/index.html";

  buf = http_get_cache( item: location, port: port );
  if( buf !~ '[Ss]erver: [Dd][Ww][ ]?[Ss]pectrum' && buf !~ '[Ss]erver:[^\r\n]*[Dd]igital [Ww]atch[Dd]og' )
    continue;

  conclUrl = report_vuln_url( port: port, url: location, url_only: TRUE );

  set_kb_item( name: "digital_watchdog/detected", value: TRUE );
  set_kb_item( name: "digital_watchdog/http/port", value: port );

  version = "unknown";
  vers = eregmatch( string: buf, pattern: '[Ss]erver: [Dd][Ww][ ]?[Ss]pectrum/([0-9.]+)' );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    set_kb_item( name: "digital_watchdog/version", value: version );
  }

  register_and_report_cpe( app: "Digital Watchdog Spectrum",
                           ver: version,
                           concluded: ver[0],
                           base: CPE,
                           expr: '([0-9.]+)',
                           insloc: dir,
                           regPort: port,
                           conclUrl: conclUrl );
  exit( 0 );
}
exit( 0 );
