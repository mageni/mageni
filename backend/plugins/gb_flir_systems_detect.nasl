###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flir_systems_detect.nasl 12915 2018-12-31 14:02:47Z asteins $
#
# FLIR Systems Camera Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.140400");
  script_version("$Revision: 12915 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-31 15:02:47 +0100 (Mon, 31 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-09-26 16:12:38 +0700 (Tue, 26 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("FLIR Systems Camera Detection");

  script_tag(name:"summary", value:"Detection of FLIR Systems Cameras.

  The script sends a connection request to the server and attempts to detect FLIR Systems Cameras and to extract
  its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.flir.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8081);

res = http_get_cache(port: port, item: "/");

if ("<title>FLIR Systems, Inc. </title>" >< res && 'id="sensortype"' >< res && ("DIALOG_SEC_PASS_CUR" >< res || "securityPassCurrentLabel" >< res)) {
  version = "unknown";

  vers = eregmatch(pattern: "flir\.base\.js\?_v=([0-9.]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "flir_camera/version", value: version);
  }

  model_match = eregmatch(pattern: '<input type="hidden" id="productName" value="([^\"\n]+)', string: res, icase: TRUE);
  if (!isnull(model_match[1])) {
    model = model_match[1];
    set_kb_item(name: "flir_camera/model", value: model);
  }

  set_kb_item(name: "flir_camera/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:flir_systems:camera:");
  if (!cpe)
    cpe = 'cpe:/a:flir_systems:camera';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "FLIR Systems Camera", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
