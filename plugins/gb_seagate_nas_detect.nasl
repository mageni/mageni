###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_seagate_nas_detect.nasl 12260 2018-11-08 12:46:52Z cfischer $
#
# Seagate NAS Device Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141184");
  script_version("$Revision: 12260 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-08 13:46:52 +0100 (Thu, 08 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-06-15 09:53:35 +0700 (Fri, 15 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Seagate NAS Device Detection");

  script_tag(name:"summary", value:"Detection of Seagate NAS devices.

The script sends a connection request to the server and attempts to detect Seagate NAS devices and to extract
its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.seagate.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/");

if ("NAS_CUSTOM_INFO" >< res && 'NAS_CUSTOM_INFO["VENDOR_NAME"]' >< res) {
  version = "unknown";

  url = '/api/external/7.0/system.System.get_infos';
  req = http_post(port: port, item: url, data: "{}");
  res = http_keepalive_send_recv(port: port, data: req);

  # {"infos": {"__sub_version__": 0, "__version__": 7, "__type__": "GeneralInfo",
  # "__properties__": {"vendor_custom_id": "", "product": "2-Bay NAS", "vendor_id": "", "product_id": "dart2",
  # "install_id": "7246f1e10a330658e285444958b136cf19144eae8b", "hardware_id": "n090201",
  # "friendly_name": "Seagate-D2", "puid": "0010754DC2DF", "version": "4.3.18.6", "serial_number": "NA6C20V3",
  # "vendor_name": "Seagate"}}}
  prod = eregmatch(pattern: '"product": "([^"]+)', string: res);
  if (!isnull(prod[1])) {
    product = prod[1];
    set_kb_item(name: "seagate_nas/model", value: product);
  }
  else
    exit(0);

  vers = eregmatch(pattern: '"version": "([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = url;
  }

  set_kb_item(name: "seagate_nas/detected", value: TRUE);

  cpe_base = 'cpe:/h:seagate:' + str_replace(string: tolower(product), find: " ", replace: "_");

  cpe = build_cpe(value: version, exp: "([0-9.]+)", base: cpe_base + ":");
  if (!cpe)
    cpe = cpe_base;

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Seagate " + product, version: version, install: "/",
                                           cpe: cpe, concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
