###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_abb_m2m_ethernet_detect.nasl 12840 2018-12-20 06:16:18Z ckuersteiner $
#
# ABB M2M ETHERNET Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141800");
  script_version("$Revision: 12840 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-20 07:16:18 +0100 (Thu, 20 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-20 11:33:24 +0700 (Thu, 20 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ABB M2M ETHERNET Detection");

  script_tag(name:"summary", value:"Detection of ABB M2M ETHERNET .

The script sends a connection request to the server and attempts to detect ABB M2M ETHERNET and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://new.abb.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8080);

res = http_get_cache(port: port, item: "/");

if ("<title>M2M Ethernet</title>" >< res && "/protect/auth.htm" >< res) {
  version = "unknown";

  # <div> FW ver. 2.22 <br/> ETH-FW ver. 1.01 </div>
  vers = eregmatch(pattern: "FW ver\. ([0-9.]+)", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  eth_vers = eregmatch(pattern: "ETH-FW ver\. ([0-9.]+)", string: res);
  if (!isnull(eth_vers[1])) {
    extra = "ETH-FW version:    " + eth_vers[1];
    set_kb_item(name: "abb_m2m_ethernet/eth_fw_version", value: eth_vers[1]);
  }

  set_kb_item(name: "abb_m2m_ethernet/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:abb:m2m_ethernet_firmware:");
  if (!cpe)
    cpe = 'cpe:/a:abb:m2m_ethernet_firmware';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "ABB M2M ETHERNET", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], extra: extra),
              port: port);
  exit(0);
}

exit(0);
