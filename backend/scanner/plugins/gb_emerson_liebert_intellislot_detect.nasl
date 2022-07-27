###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emerson_liebert_intellislot_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Emerson Liebert IntelliSlot WebCard Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.113234");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-07-24 11:08:10 +0200 (Tue, 24 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Emerson Liebert InstelliSlot WebCard Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Emerson Lieber IntelliSlot WebCard Detection Devices.");

  # https://www.elektroniknet.de/markt-technik/power/aus-emerson-network-power-wird-vertiv-136676.html
  script_xref(name:"URL", value:"https://www.vertivco.com/en-us/products/brands/liebert/");

  exit(0);
}

CPE = "cpe:/h:liebert:intellislot:";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc" );

port = get_http_port( default: 80 );
buf = http_get_cache( item: "/", port: port );

if( buf =~ '<title>(Emerson|Vertiv)[^<]*Intelli[Ss]lot (Web)?[^A-Za-z<]* Card</title>'
    && buf =~ 'content="Liebert Corporation' ) {
  set_kb_item( name: "liebert/intellislot/detected", value: TRUE );
  set_kb_item( name: "liebert/intellislot/http/port", value: port );

  version = "unknown";
  buf = http_get_cache( item: "/support/support.htm", port: port );

  conclUrl = "/";
  vers = eregmatch( string: buf, pattern: '<td>Agent App Firmware Version</td><td align="left">([0-9A-Z.]+)</td>' );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    conclUrl = "/support/support.htm";
  }

  register_and_report_cpe( app: "Emerson Liebert InstelliSlot WebCard",
                           ver: version,
                           concluded: vers[0],
                           base: CPE,
                           expr: '([0-9A-Z.]+)',
                           insloc: '/',
                           regPort: port,
                           conclUrl: conclUrl );

}

exit( 0 );
