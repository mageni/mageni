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
  script_oid("1.3.6.1.4.1.25623.1.0.113764");
  script_version("2020-10-08T13:07:46+0000");
  script_tag(name:"last_modification", value:"2020-10-09 10:01:41 +0000 (Fri, 09 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-09-29 12:29:00 +0200 (Tue, 29 Sep 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Trend Micro Threat Discovery Appliance Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Checks whether the target is a Trend Micro Threat Discovery Appliance.");

  script_xref(name:"URL", value:"https://docs.trendmicro.com/all/ent/tms/v2.6/en-us/tda_2.6_olh/help/intro/about_threat_discovery_appliance.htm");

  exit(0);
}

CPE = "cpe:/a:trendmicro:threat_discovery:";

include( "host_details.inc" );
include( "misc_func.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "port_service_func.inc" );
include( "cpe.inc" );

port = http_get_port( default: 80 );
buf = http_get_cache( port: port, item: "/" );

if( buf =~ "title>Trend Micro Threat Discovery Appliance Logon</title>" && buf =~ "Trend Micro Incorporated" )
{
  version = "unknown";

  set_kb_item( name: "trendmicro/threat_discovery/detected", value: TRUE );
  register_and_report_cpe( app: "Trend Micro Thread Discovery Appliance",
                           ver: version,
                           base: CPE,
                           expr: '([0-9.]+)',
                           insloc: port + "/tcp",
                           regPort: port,
                           regProto: "tcp",
                           conclUrl: "/" );
}

exit( 0 );
