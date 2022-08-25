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
  script_oid("1.3.6.1.4.1.25623.1.0.105862");
  script_version("2022-08-22T10:11:10+0000");
  script_tag(name:"last_modification", value:"2022-08-22 10:11:10 +0000 (Mon, 22 Aug 2022)");
  script_tag(name:"creation_date", value:"2016-08-11 15:53:38 +0200 (Thu, 11 Aug 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("VMware vRealize Operations Manager Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of VMware vRealize Operations Manager.");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.vmware.com/products/vrealize-operations.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("os_func.inc");

port = http_get_port( default:443 );

url = "/admin/login.action";
buf = http_get_cache( item:url, port:port );

if( buf !~ "<title>vRealize Operations( Manager)?" ) {
  url = "/ui/login";
  buf = http_get_cache( item:url, port:port );
}

if( buf =~ "<title>vRealize Operations( Manager)?" ) {
  version = "unknown";
  build = "unknown";

  api_url = "/suite-api/api/versions/current";
  req = http_get( item:api_url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  # <ops:releaseName>VMware vRealize Operations Manager 6.1.0</ops:releaseName>
  # <ops:releaseName>VMware vRealize Operations 8.6.3</ops:releaseName>
  vers = eregmatch( pattern:"<ops:releaseName>VMware vRealize Operations (Manager )?([0-9.]+)", string:res );
  if( ! isnull( vers[2] ) )
    version = vers[2];

  # <ops:buildNumber>3038036</ops:buildNumber>
  b = eregmatch( pattern:"<ops:buildNumber>([0-9]+[^<]+)</ops:buildNumber>", string:res );
  if( ! isnull( b[1] ) ) {
    build = b[1];
    set_kb_item( name:"vmware/vrealize/operations_manager/build", value:build );
  }

  set_kb_item( name:"vmware/vrealize/operations_manager/detected", value:TRUE );
  set_kb_item( name:"vmware/vrealize/operations_manager/http/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:vmware:vrealize_operations_manager:" );
  if( ! cpe )
    cpe = "cpe:/a:vmware:vrealize_operations_manager";

  os_register_and_report( os:"VMware Photon OS", cpe:"cpe:/o:vmware:photonos",
                          desc:"VMware vRealize Operations Manager Detection (HTTP)", runs_key:"unixoide" );

  register_product( cpe:cpe, location:"/", port:port, service:"www" );

  report = build_detection_report( app:"VMware vRealize Operations Manager", version:version, build:build,
                                   install:"/", cpe:cpe, concluded:res,
                                   concludedUrl:http_report_vuln_url( port:port, url:api_url, url_only:TRUE ) );

  log_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );
