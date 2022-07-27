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
  script_oid("1.3.6.1.4.1.25623.1.0.112839");
  script_version("2020-11-16T14:32:58+0000");
  script_tag(name:"last_modification", value:"2020-11-17 11:07:05 +0000 (Tue, 17 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-16 09:14:11 +0000 (Mon, 16 Nov 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("aiohttp Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("aiohttp/banner");

  script_tag(name:"summary", value:"HTTP based detection of aiohttp.");

  script_xref(name:"URL", value:"https://docs.aiohttp.org/");

  exit(0);
}

CPE = "cpe:/a:aio-libs_project:aiohttp:";

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");

port = http_get_port( default: 443 );

buf = http_get_remote_headers( port: port );

# Server: Python/3.8 aiohttp/3.6.2
# SERVER: Image Super Proxy (aiohttp)
# Server: Python/3.6 aiohttp/3.4.4
if( concl = egrep( string: buf, pattern: "^Server\s*:.*aiohttp", icase: TRUE ) ) {

  set_kb_item( name: "aio-libs_project/aiohttp/detected", value: TRUE );

  concl = chomp( concl );
  version = "unknown";

  ver = eregmatch( string: concl, pattern: "aiohttp/([0-9.]+)" );
  if( ! isnull( ver[1] ) )
    version = ver[1];

  register_and_report_cpe( app: "aiohttp",
                           ver: version,
                           concluded: concl,
                           base: CPE,
                           expr: "([0-9.]+)",
                           insloc: port + "/tcp",
                           regPort: port,
                           regService: "www" );
}

exit( 0 );
