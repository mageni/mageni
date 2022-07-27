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
  script_oid("1.3.6.1.4.1.25623.1.0.105864");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-10-18T12:03:27+0000");
  script_tag(name:"last_modification", value:"2021-10-19 10:35:24 +0000 (Tue, 19 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-08-12 11:45:40 +0200 (Fri, 12 Aug 2016)");

  script_name("VMware vRealize Orchestrator Detection (HTTP)");

  script_tag(name:"qod_type", value:"remote_active");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8281);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of VMware vRealize Orchestrator.");

  script_xref(name:"URL", value:"https://www.vmware.com/products/vrealize-orchestrator.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:8281 );

url = "/vco/";
res = http_get_cache( port:port, item:url );

if( "<title>VMware vRealize Orchestrator</title>" >< res &&
    ( "Orchestrator Control Center" >< res || res =~ "> (START THE|OPEN) CONTROL CENTER<" ) ) {
  version = "unknown";
  install = "/";

  # <span>VMware vRealize Orchestrator 7.6.0</span>
  # nb: Older ones had the following (a "[\n ]*" regex had been used after the first ">"):
  # <div id="appliance-info">VMware vRealize Orchestrator 7.0.1
  #
  vers = eregmatch( pattern:"VMware vRealize Orchestrator ([0-9.]+)", string:res );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }

  set_kb_item( name:"vmware/vrealize/orchestrator/detected", value:TRUE );
  set_kb_item( name:"vmware/vrealize/orchestrator/http/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:vmware:vrealize_orchestrator:" );
  if( ! cpe )
    cpe = "cpe:/a:vmware:vrealize_orchestrator";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"VMware vRealize Orchestrator", version:version,
                                            install:install, cpe:cpe, concluded:vers[0],
                                            concludedUrl:concUrl ),
               port:port );
}

exit( 0 );