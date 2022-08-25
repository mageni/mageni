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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809341");
  script_version("2022-08-22T10:11:10+0000");
  script_tag(name:"last_modification", value:"2022-08-22 10:11:10 +0000 (Mon, 22 Aug 2022)");
  script_tag(name:"creation_date", value:"2016-10-06 14:54:29 +0530 (Thu, 06 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache ActiveMQ Artemis Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Apache ActiveMQ Artemis.");

  script_xref(name:"URL", value:"https://activemq.apache.org/components/artemis/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

url = "/api/index.html";

res = http_get_cache( port:port, item:url );

# <title>Overview (ActiveMQ Artemis Web 2.20.0 API)</title>
# <title>ActiveMQ Artemis Web 2.4.0 API</title>
if( res =~ "<title>(Overview \()?ActiveMQ Artemis Web .* API\)?</title>" || 'WWW-Authenticate: basic realm="ActiveMQ"' >< res ) {
  version = "unknown";
  install = "/";
  conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

  vers = eregmatch( pattern:"ActiveMQ Artemis Web ([0-9.]+) API", string:res );
  if( ! isnull( version[1] ) )
    version = vers[1];

  set_kb_item( name:"apache/activemq/artemis/detected", value:TRUE );
  set_kb_item( name:"apache/activemq/artemis/http/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:activemq_artemis:" );
  if( ! cpe )
    cpe = "cpe:/a:apache:activemq_artemis";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Apache ActiveMQ Artemis", install:install, version:version,
                                            concluded:vers[0], concludedUrl:conclUrl, cpe:cpe ),
               port:port );
}

exit( 0 );
