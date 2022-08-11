###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zycoo_ip_phone_system_detect.nasl 11407 2018-09-15 11:02:05Z cfischer $
#
# ZYCOO IP Phone System Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.106213");
  script_version("$Revision: 11407 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:02:05 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-08-29 14:37:34 +0700 (Mon, 29 Aug 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ZYCOO IP Phone System Detection");

  script_tag(name:"summary", value:"Detection of ZYCOO IP Phone System

  The script sends a connection request to the server and attempts to detect the presence of ZYCOO IP Phone System
  and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 9999);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.zycoo.com/html/IP_Phone_System.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 9999);

req = http_get(port: port, item: "/scripts/branding.js");
res = http_keepalive_send_recv(port: port, data: req);

if ("ZYCOO IP Phone System" >< res) {
  model = "unknown";
  version = "unknown";

  mo = eregmatch(pattern: "\['PBX_Model'\] = '([A-Za-z0-9-]+)", string: res);
  if (!isnull(mo[1])) {
    model = mo[1];
    set_kb_item(name: "zycoo_ipphonesystem/model", value: model);
  }

  ver = eregmatch(pattern: "\['HideVersion'\] = branding\['PBX_Model'\] \+ '-([0-9.]+)", string: res);
  if (!isnull(ver[1])) {
    version = ver[1];
    set_kb_item(name: "zycoo_ipphonesystem/version", value: version);
  }

  set_kb_item(name: "zycoo_ipphonesystem/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:zycoo:ip_phone_system:");
  if (!cpe)
    cpe = 'cpe:/a:zycoo:ip_phone_system';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "ZYCOO IP Phone System " + model, version: version, install: "/",
                                           cpe: cpe, concluded: ver[0]),
              port: port);
  exit(0);
}

exit(0);
