###############################################################################
# OpenVAS Vulnerability Test
#
# PrinterOn Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.141109");
  script_version("2019-04-25T12:09:35+0000");
  script_tag(name:"last_modification", value:"2019-04-25 12:09:35 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-05-18 14:11:47 +0700 (Fri, 18 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("PrinterOn Detection");

  script_tag(name:"summary", value:"Detection of PrinterOn.

The script sends a connection request to the server and attempts to detect PrinterOn and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.printeron.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

url = '/cps/Login';
res = http_get_cache(port: port, item: url);

if ("<title>PrinterOn Printing Service</title>" >< res && "GUEST LOG IN" >< res) {
  version = "unknown";

  vers = eregmatch(pattern: 'both;">v([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = url;
  }

  set_kb_item(name: "printeron/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:printeron:printeron:");
  if (!cpe)
    cpe = 'cpe:/a:printeron:printeron';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "PrinterOn", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
