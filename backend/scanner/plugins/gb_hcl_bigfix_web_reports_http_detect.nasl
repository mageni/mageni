# Copyright (C) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140069");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2022-05-09T06:06:23+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"creation_date", value:"2016-11-21 10:22:25 +0100 (Mon, 21 Nov 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HCL / IBM BigFix Web Reports Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of HCL / IBM BigFix Web Reports.");

  script_xref(name:"URL", value:"https://www.hcltechsw.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

res = http_get_cache( port:port, item:"/" );

if( "<title>Login" >!< res || "BigFix Web Reports</title>" >!< res )
  exit( 0 );

set_kb_item( name:"hcl/bigfix/web_reports/detected", value:TRUE );
set_kb_item( name:"hcl/bigfix/web_reports/http/detected", value:TRUE );

version = "unknown";

#<div id="wr_versionHeader">
#                        version 9.5.3.211
#                     </div>
vers = eregmatch( pattern:'(<div id="wr_versionHeader">.*version ([0-9.]+)[^<]*</div>)', string:res );
if( ! isnull( vers[2] ) )
  version = vers[2];

cpe1 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:hcltech:bigfix_webreports:" );
cpe2 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:ibm:bigfix_webreports:" );
if( ! cpe ) {
  cpe1 = "cpe:/a:hcltech:bigfix_webreports";
  cpe2 = "cpe:/a:ibm:bigfix_webreports";
}

register_product( cpe:cpe1, location:"/", port:port, service:"www" );
register_product( cpe:cpe2, location:"/", port:port, service:"www" );

log_message( data:build_detection_report( app:"HCL BigFix Web Reports", version:version, install: "/",
                                          cpe:cpe1, concluded:vers[0] ),
             port:port );

exit( 0 );
