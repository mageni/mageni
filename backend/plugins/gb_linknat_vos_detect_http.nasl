###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_linknat_vos_detect_http.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Linknat VOS SoftSwitch Detection (HTTP)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106086");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-26 11:12:13 +0700 (Thu, 26 May 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Linknat VOS SoftSwitch Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Linknat VOS SoftSwitch

The script attempts to identify Linknat VOS SoftSwitch via HTTP requests to extract the
model and version number.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");


  script_xref(name:"URL", value:"http://www.linknat.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

url = '/eng/js/lang_en_us.js';
req = http_get(item: url, port: port);
res = http_keepalive_send_recv(port: port, data: req);

if ("Welcome to Web Self-Service System" >< res && "GatewayPasswordModification" >< res) {
  model = 'unknown';
  mo = eregmatch(pattern: 's\\[8\\] = \\"(VOS[0-9]{4})', string: res);
  if (!isnull(mo[1]))
    model = mo[1];

  version = 'unknown';
  ver = eregmatch(pattern: 'Version: ([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)', string: res);
  if (!isnull(ver[1]))
    version = ver[1];

  set_kb_item(name: 'linknat_vos/detected', value: TRUE);
  set_kb_item(name: 'linknat_vos/http/port', value: port);

  if (model != 'unknown')
    set_kb_item(name: 'linknat_vos/http/model', value: model);

  if (version != 'unknown')
    set_kb_item(name: 'linknat_vos/http/version', value: version);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: 'cpe:/a:linknat:vos:' + tolower(model) + ':');
  if (isnull(cpe)) {
    if (model != 'unknown')
      cpe = "cpe:/a:linknat:vos:" + model;
    else
      cpe = "cpe:/a:linknat:vos";
  }

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Linknat SoftSwitch " + model,
                                           version: version,
                                           install: "/",
                                           cpe: cpe, concluded: ver[0]),
              port: port);
}

exit(0);

