##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cyberoam_umt_ngfw_detect.nasl 10896 2018-08-10 13:24:05Z cfischer $
#
# Sophos Cyberoam UMT/NGFW Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106864");
  script_version("$Revision: 10896 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:24:05 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-06-12 15:55:23 +0700 (Mon, 12 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sophos Cyberoam UMT/NGFW Detection");

  script_tag(name:"summary", value:"Detection of Sophos Cyberoam UMT/NGFW.

The script sends a connection request to the server and attempts to detect Sophos Cyberoam UMT/NGFW
devices and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.cyberoam.com/networksecurity.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/corporate/webpages/login.jsp");

if ("<title>Cyberoam</title>" >< res && "OWN_STATUS" >< res && "AUXILIARY" >< res) {
  version = "unknown";

  vers = eregmatch(pattern: "ver=([0-9.]+) build ([0-9])([0-9]+)", string: res);
  if (!isnull(vers[1]) && !isnull(vers[2]) && !isnull(vers[3])) {
    # we get something like 10.06 build 5050 which is actually 10.06.5 build 050
    version = vers[1] + '.' + vers[2] + '.' + vers[3];
    set_kb_item(name: "cyberoam_umt_ngfw/version", value: version);
  }

  set_kb_item(name: "cyberoam_umt_ngfw/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:cyberoam:cyberoam_os:");
  if (!cpe)
    cpe = 'cpe:/o:cyberoam:cyberoam_os';

  register_product(cpe: cpe, location: "/", port: port, service: "www");
  register_and_report_os(os: "Cyberoam OS", cpe: cpe, port: port, banner_type: "HTTP login page",
                         desc: "Cyberoam Detection", runs_key: "unixoide");

  log_message(data: build_detection_report(app: "Sophos Cyberoam UMT/NGFW", version: version, install: "/",
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
