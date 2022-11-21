# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113596");
  script_version("2022-11-18T12:56:30+0000");
  script_tag(name:"last_modification", value:"2022-11-18 12:56:30 +0000 (Fri, 18 Nov 2022)");
  script_tag(name:"creation_date", value:"2019-11-29 12:44:44 +0200 (Fri, 29 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("EmWeb Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("emweb/banner");

  script_tag(name:"summary", value:"HTTP based detection of EmWeb.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");

port = http_get_port( default: 80 );

buf = http_get_remote_headers( port: port );

if( concl = egrep( string: buf, pattern: '^Server\\s*:[^\n]*-EmWeb', icase: TRUE ) ) {

  concl = chomp( concl );

  set_kb_item( name: "emweb/detected", value: TRUE );
  set_kb_item( name: "emweb/http/detected", value: TRUE );

  version = "unknown";
  model = "";

  ver = eregmatch( string: buf, pattern: "([A-Za-z]+)-EmWeb/R([0-9._]+)" );
  if( ! isnull( ver[2] ) ) {
    version = str_replace( string: ver[2], find:"_", replace:"." );
    model = ver[1];
    set_kb_item( name: tolower( model ) + "/emweb/detected", value: TRUE );
    CPE = "cpe:/a:" + tolower( model ) + ":emweb:";
    app_name = model + " EmWeb";
  } else {
    CPE = "cpe:/a:virata:emweb:";
    app_name = "EmWeb";
  }

  register_and_report_cpe( app: app_name,
                           ver: version,
                           concluded: concl,
                           base: CPE,
                           expr: "([0-9.]+)",
                           insloc: port + "/tcp",
                           regPort: port,
                           regService: "www" );
}

exit( 0 );
