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
  script_oid("1.3.6.1.4.1.25623.1.0.107062");
  script_version("2021-05-27T04:37:21+0000");
  script_tag(name:"last_modification", value:"2021-05-27 10:33:26 +0000 (Thu, 27 May 2021)");
  script_tag(name:"creation_date", value:"2016-10-19 13:26:09 +0700 (Wed, 19 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Nagios Network Analyzer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Nagios Network Analyzer.");

  script_xref(name:"URL", value:"https://www.nagios.com/products/nagios-network-analyzer/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/nagiosna", "/nagios", http_cgi_dirs(port: port))) {
  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php/login";
  res = http_get_cache(port: port, item: url);

  if ("<title>Login &bull; Nagios Network Analyzer</title>" >< res && "nnalogo_small.png" >< res) {
    version = "unknown";

    set_kb_item(name: "nagios/network_analyzer/detected", value: TRUE);

    vers = eregmatch(pattern: 'var NA_VERSION = "([0-9.]+)"', string: res, icase: TRUE);
    if (isnull(vers[1]))
      vers = eregmatch(pattern: 'ver=([0-9.]+)">', string: res);

    if (!isnull(vers[1]))
      vers = vers[1];

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:nagios:network_analyzer:");
    if (!cpe)
      cpe = "cpe:/a:nagios:network_analyzer";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app:"Nagios Network Analyzer", version:version, install: install,
                                            cpe: cpe, concluded: vers[0]),
                port:port);
    exit(0);
  }
}

exit(0);
