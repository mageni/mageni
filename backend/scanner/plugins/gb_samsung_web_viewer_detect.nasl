###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samsung_web_viewer_detect.nasl 10915 2018-08-10 15:50:57Z cfischer $
#
# Samsung Web Viewer Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140509");
  script_version("$Revision: 10915 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:50:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-11-16 13:25:30 +0700 (Thu, 16 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Samsung SRN Device Detection");

  script_tag(name:"summary", value:"Detection of Samsung Web Viewer.

Samsung Web Viewer is normally part of Samsung SRN devices.

The script sends a connection request to the server and attempts to detect Samsung Web Viewer and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.samsungcc.com.au/cctv/ip-nvr-solution");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/");

if ("<title>Web Viewer for Samsung NVR</title>" >< res &&
    ("/js/boot_status.html" >< res || "/webviewer?ip=" >< res)) {
  version = "unknown";

  vers = eregmatch(pattern: "File Version ([0-9.]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "samsung_webviewer/version", value: version);
  }

  set_kb_item(name: "samsung_webviewer/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:samsung:web_viewer:");
  if (!cpe)
    cpe = 'cpe:/a:samsung:web_viewer';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Samsung Web Viewer", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
