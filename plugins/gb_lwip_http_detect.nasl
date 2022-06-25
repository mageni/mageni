# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108825");
  script_version("2020-07-30T12:46:38+0000");
  script_tag(name:"last_modification", value:"2020-07-31 10:00:11 +0000 (Fri, 31 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-30 07:52:41 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("lwIP TCP/IP Stack Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of the lwIP TCP/IP stack.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("lwIP/banner");

  script_xref(name:"URL", value:"https://savannah.nongnu.org/projects/lwip");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );

if( ! banner = http_get_remote_headers( port:port ) )
  exit( 0 );

# Server: lwIP/1.4.0 (http://savannah.nongnu.org/projects/lwip)
# Server: lwIP/1.3.2
# Server: lwIP/1.3.2 (http://www.sics.se/~adam/lwip/)
# Server: lwIP/1.3.1 (http://savannah.nongnu.org/projects/lwip)
# Server: lwIP/1.3.0 (http://www.sics.se/~adam/lwip/)
# Server: lwIP
if( ! match = egrep( string:banner, pattern:"^Server\s*:\s*lwIP", icase:TRUE ) )
  exit( 0 );

set_kb_item( name:"lwip/detected", value:TRUE );
match = chomp( match );
version = "unknown";
vers = eregmatch( string:match, pattern:"Server\s*:\s*lwIP/([0-9.]+)", icase:TRUE );
if( vers )
  version = vers[1];

register_and_report_cpe( app:"lwIP TCP/IP Stack",
                         ver:version,
                         concluded:match,
                         base:"cpe:/a:lwip_project:lwip:",
                         expr:"([0-9.]+)",
                         insloc:port + "/tcp",
                         regPort:port,
                         regService:"www" );

exit( 0 );
