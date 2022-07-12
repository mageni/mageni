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
  script_oid("1.3.6.1.4.1.25623.1.0.114077");
  script_version("$Revision: 13911 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 15:46:42 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-27 13:40:02 +0100 (Wed, 27 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("TP-Link Megapixel Surveillance Camera Detection");

  script_tag(name:"summary", value:"Detection of Megapixel Surveillance Camera.

  The script sends a connection request to the server and attempts to detect the web interface for TP-Link's Megapixel Surveillance Camera.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.tp-link.com/download/TL-SC3430N.html#Firmware");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = "/prod";
res = http_get_cache(port: port, item: url);

#Response looks like this:
#var initProdShortName="Wireless N H.264+Mega Camera"
#var initProdFullName="Wireless N H.264 Megapixel Surveillance Camera"
#var initProdNbr="TL-SC3430N"
if("Megapixel Surveillance Camera" >< res && res =~ 'initProdNbr="[^"]+"') {
  version = "unknown";
  install = "/";

  conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);

  model = eregmatch(pattern: 'initProdNbr="([^"]+)"', string: res, icase: TRUE);

  if(!isnull(model[1]))
    set_kb_item(name: "tp-link/wireless/megapixel_surveillance_camera/model", value: model[1]);

  set_kb_item(name: "tp-link/wireless/megapixel_surveillance_camera/detected", value: TRUE);
  set_kb_item(name: "tp-link/wireless/megapixel_surveillance_camera/" + port + "/detected", value: TRUE);

  cpe = "cpe:/h:tp-link:megapixel_surveillance_camera";

  register_and_report_cpe(app: "TP-Link Megapixel Surveillance Camera",
                          ver: version,
                          concluded: "TP-Link Megapixel Surveillance Camera " + model[1],
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: install,
                          regPort: port,
                          regService: "www",
                          conclUrl: conclUrl,
                          extra: "Version detection requires login.");
}

exit(0);
