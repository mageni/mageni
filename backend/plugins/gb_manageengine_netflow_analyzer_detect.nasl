###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_netflow_analyzer_detect.nasl 10902 2018-08-10 14:20:55Z cfischer $
#
# ManageEngine NetFlow Analyzer Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.140778");
  script_version("$Revision: 10902 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:20:55 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-02-15 17:20:38 +0700 (Thu, 15 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ManageEngine NetFlow Analyzer Detection");

  script_tag(name:"summary", value:"Detection of ManageEngine NetFlow Analyzer.

The script sends a connection request to the server and attempts to detect ManageEngine NetFlow Analyzer and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.manageengine.com/products/netflow/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/apiclient/ember/Login.jsp");

if ("NetFlow Analyzer" >< res && "'info'>The Complete Traffic Analytics Software" >< res) {
  version = "unknown";

  # NetFlow Analyzer<span>v 12.0</span>
  # This is not that reliable since no build information available
  vers = eregmatch(pattern: "NetFlow Analyzer<span>v ([0-9.]+)<", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "me_netflow_analyzer/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:zohocorp:manageengine_netflow_analyzer:");
  if (!cpe)
    cpe = 'cpe:/a:zohocorp:manageengine_netflow_analyzer';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "ManageEngine NetFlow Analyzer", version: version,
                                           install: "/", cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
