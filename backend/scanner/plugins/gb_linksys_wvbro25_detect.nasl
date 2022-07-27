###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_linksys_wvbro25_detect.nasl 10891 2018-08-10 12:51:28Z cfischer $
#
# Linksys WVBRO-25 Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.140624");
  script_version("$Revision: 10891 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:51:28 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-12-22 13:08:48 +0700 (Fri, 22 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Linksys WVBRO-25 Detection");

  script_tag(name:"summary", value:"Detection of Linksys WVBRO-25.

The script sends a connection request to the server and attempts to detect Linksys WVBRO-25 and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("lighttpd/banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

banner = get_http_banner(port: port);
if ("lighttpd" >!< banner)
  exit(0);

res = http_get_cache(port: port, item: "/");

if ("Vendor:LINKSYS" >< res && "ModelName:WVBR0-25" >< res) {
  version = "unknown";

  mod = eregmatch(pattern: 'ModelName:([^\n\r]+)', string: res);
  if (isnull(mod[1]))
    exit(0);

  model = mod[1];

  vers = eregmatch(pattern: "Firmware Version: ([0-9.]+)", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  mac = eregmatch(pattern: "device::mac_addr=([a-fA-F0-9:]{17})", string: res);
  if (!isnull(mac[1])) {
    extra = "Mac Address:   " + mac[1] + '\n';
    register_host_detail(name: "MAC", value: mac[1], desc: "gb_linksys_wvbro25_detect.nasl");
    replace_kb_item(name: "Host/mac_address", value: mac[1]);
  }

  set_kb_item(name: "linksys_wvbr0/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:linksys:wvbr0:");
  if (!cpe)
    cpe = 'cpe:/a:linksys:wvbr0';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Linkys " + model, version: version, install: "/", cpe: cpe,
                                           concluded: vers[0],extra: extra),
              port: port);
  exit(0);
}

exit(0);
