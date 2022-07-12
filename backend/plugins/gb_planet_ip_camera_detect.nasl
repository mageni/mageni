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
  script_oid("1.3.6.1.4.1.25623.1.0.114067");
  script_version("$Revision: 13505 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 14:38:12 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-06 13:39:57 +0100 (Wed, 06 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Planet IP Camera Detection");

  script_tag(name:"summary", value:"Detection of Planet IP Camera.

  The script sends a connection request to the server and attempts to detect the web interface for Planet's IP camera.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.planet.com.tw/en/products/ip-surveillance");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = "/scripts/lan_0_m.xml";
res = http_get_cache(port: port, item: url);

if("PLANET Techonolgy Co., LTD.:</copyright>" >!< res) {
  url = "/";
  res = http_get_cache(port: port, item: url);
}

if("PLANET Techonolgy Co., LTD.:</copyright>" >< res || 'WWW-Authenticate: Basic realm="PLANET IP CAM"' >< res) {
  version = "unknown";
  install = "/";

  conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);
  cpe = "cpe:/a:planet:ip_camera:";

  set_kb_item(name: "planet/ip_camera/detected", value: TRUE);
  set_kb_item(name: "planet/ip_camera/" + port + "/detected", value: TRUE);

  register_and_report_cpe(app: "Planet IP Camera",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: install,
                          regPort: port,
                          conclUrl: conclUrl,
                          extra: "Version detection requires login.");
}

exit(0);
