# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.146646");
  script_version("2021-09-07T05:45:38+0000");
  script_tag(name:"last_modification", value:"2021-09-07 10:21:00 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-06 14:17:32 +0000 (Mon, 06 Sep 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WikyBlog Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of WikyBlog.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.wikyblog.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/blog", "/Wiky", http_cgi_dirs(port: port))) {
  install = dir;

  if (dir == "/")
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache(port: port, item: url);

  # <span>Powered by <a href="http://www.wikyblog.com" title="WikyBlog, not exactly a wiki, not exactly a blog." >WikyBlog<
  if ('<span>Powered by <a href="http://www.wikyblog.com"' >< res && ">WikyBlog<" >< res) {
    version = "unknown";

    set_kb_item(name: "wikyblog/detected", value: TRUE);
    set_kb_item(name: "wikyblog/http/detected", value: TRUE);

    cpe = "cpe:/a:wikyblog:wikyblog";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "WikyBlog", version: version, install: install,
                                             cpe: cpe),
                port: port);
    exit(0);
  }
}

exit(0);