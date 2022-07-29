# Copyright (C) 2009 LSS Security Team
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
  script_oid("1.3.6.1.4.1.25623.1.0.100285");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2022-07-26T10:10:42+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:42 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2009-10-02 19:48:14 +0200 (Fri, 02 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Photopost Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2009 LSS / Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Photopost.");

  script_xref(name:"URL", value:"http://www.photopost.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/photopost", "/photos", "/gallery", "/photo", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if (!res)
    continue;

  match = egrep(pattern: "Powered by[^>]*>(<font[^>]*>)?PhotoPost", string: res, icase: TRUE);
  if (match || ("Photo Sharing Gallery by PhotoPost" >< res && "http://www.photopost.com" >< res)) {
    version = "unknown";

    match = egrep(pattern: "Powered by[^>]*>(<font[^>]*>)?PhotoPost.*PHP ([0-9.a-z]+)", string: res,
                  icase: TRUE);
    if (match)
      item = eregmatch(pattern: "Powered by[^>]*>(<font[^>]*>)?PhotoPost.*PHP ([0-9.]+([a-z0-9]+)?)", string: match,
                       icase:TRUE);
    if (!isnull(item[2]))
      version = item[2];

    set_kb_item(name: "photopost/detected", value: TRUE);
    set_kb_item(name: "photopost/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+([a-z0-9]+)?)", base: "cpe:/a:photopost:photopost_php_pro:");
    if (!cpe)
      cpe = "cpe:/a:photopost:photopost_php_pro";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "PhotoPost", version: version, install: install, cpe: cpe,
                                             concluded: item[0]),
                port: port);
    exit(0);
  }
}

exit(0);
