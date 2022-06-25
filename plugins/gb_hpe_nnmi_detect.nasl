###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_nnmi_detect.nasl 4568 2016-11-18 09:58:27Z ckuerste $
#
# HP Network Node Manager i (NNMi) Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.106400");
  script_version("$Revision: 4568 $");
  script_tag(name:"last_modification", value:"$Date: 2016-11-18 10:58:27 +0100 (Fri, 18 Nov 2016) $");
  script_tag(name:"creation_date", value:"2016-11-18 10:07:02 +0700 (Fri, 18 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HP Network Node Manager i (NNMi) Detection");

  script_tag(name:"summary", value:"Detection of HP Network Node Manager i (NNMi)

  The script sends a connection request to the server and attempts to detect the presence of NNMi
and to extract its version");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

req = http_get(port: port, item: "/nnm/main");
res = http_keepalive_send_recv(port: port, data: req);

if ("<title>HP Network Node Manager" >< res && "The NNMi console requires" >< res) {
  version = "unknown";

  req = http_get(port: port, item: "/nnmDocs_en/htmlHelp/nmHelp/Content/nmHelp/nmWelcome.htm");
  res = http_keepalive_send_recv(port: port, data: req);

  vers = eregmatch(pattern: '_HPc_Basic_Variables_HP_Product_Version">([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "hpe/nnmi/version", value: version);
  }

  set_kb_item(name: "hpe/nnmi/installed", value: TRUE);

  cpe  = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:hp:network_node_manager_i:");
  if (!cpe)
    cpe = 'cpe:/a:hp:network_node_manager_i';

  register_product(cpe: cpe, location: "/nnm", port: port);

  log_message(data: build_detection_report(app: "HPE Network Node Manager i (NNMi)", version: version,
                                           install: "/nnm", cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
