###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nucom_device_detect.nasl 10915 2018-08-10 15:50:57Z cfischer $
#
# NuCom Device Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141262");
  script_version("$Revision: 10915 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:50:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-07-03 10:57:39 +0200 (Tue, 03 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NuCom Device Detection");

  script_tag(name:"summary", value:"Detection of NuCom devices.

The script sends a connection request to the server and attempts to detect NuCom devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.nucom.es/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/page/login/login.html");

if ("getLogStr('LK_Usernamee')" >< res && "var G_language = " >< res) {
  version = "unknown";

  mod = eregmatch(pattern: 'var Manufacturer = "([^"]+)', string: res);
  if (isnull(mod[1]))
    exit(0);

  model = mod[1];
  set_kb_item(name: "nucom_device/detected", value: TRUE);
  set_kb_item(name: "nucom_device/model", value: model);

  cpe = 'cpe:/h:nucom:' + tolower(model);

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "NuCom " + model, version: version, install: "/", cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
