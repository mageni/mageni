###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opsview_monitor_detect.nasl 11233 2018-09-05 07:16:08Z ckuersteiner $
#
# OpsView Monitor Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141428");
  script_version("$Revision: 11233 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-05 09:16:08 +0200 (Wed, 05 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-05 11:47:50 +0700 (Wed, 05 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OpsView Monitor Detection");

  script_tag(name:"summary", value:"Detection of OpsView Monitor.

The script sends a connection request to the server and attempts to detect OpsView Monitor and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.opsview.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/login");

if ("<title>Opsview login page</title>" >< res && "opsview-screens-common.css" >< res) {
  version = "unknown";

  ed = eregmatch(pattern: "Opsview Monitor (.* Edition)", string: res);
  if (!isnull(ed[1]))
    edition = ed[1];

  vers = eregmatch(pattern: "([0-9.]+) \| Copyright", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "opsview_monitor/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:opsview:opsview:");
  if (!cpe)
    cpe = 'cpe:/a:opsview:opsview';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "OpsView Monitor " + edition, version: version, install: "/",
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
