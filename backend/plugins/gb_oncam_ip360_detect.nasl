# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.114093");
  script_version("2019-04-30T13:07:52+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-04-30 13:07:52 +0000 (Tue, 30 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-30 13:02:37 +0200 (Tue, 30 Apr 2019)");
  script_name("Oncam IP 360 Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installation of
  Oncam IP 360.

  This script sends an HTTP GET request and tries to ensure the presence of
  the Oncam IP 360 web interface.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = "/";

res = http_get_cache(port: port, item: url);

if('<link href="/oncam.ico"' >< res && "WWW-Authenticate: Basic realm=IP Camera" >< res) {

  version = "unknown";

  set_kb_item(name: "oncam/ip360/detected", value: TRUE);

  verUrl = "/admin/getparam.cgi?softwareversion";
  res2 = http_get_cache(port: port, item: verUrl);

  #softwareversion=1.9.12.358L
  ver = eregmatch(pattern: "softwareversion=([0-9.]+[a-zA-Z]*)", string: res2, icase: TRUE);
  if(!isnull(ver[1]))
    version = ver[1];

  cpe = "cpe:/a:oncam:ip360:";

  conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "Oncam IP 360",
                          ver: version,
                          concluded: ver[0],
                          base: cpe,
                          expr: "^([0-9.]+[a-zA-Z]+)",
                          insloc: "/",
                          regPort: port,
                          regService: "www",
                          conclUrl: conclUrl);
}

exit(0);
