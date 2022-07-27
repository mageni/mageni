###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_acrolinx_detect.nasl 11021 2018-08-17 07:48:11Z cfischer $
#
# Acrolinx Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.140892");
  script_version("$Revision: 11021 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:48:11 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-03-28 10:10:01 +0700 (Wed, 28 Mar 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Acrolinx Detection");

  script_tag(name:"summary", value:"Detection of Acrolinx.

The script sends a connection request to the server and attempts to detect Acrolinx and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.acrolinx.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/dashboard.html");

if ("<title>Acrolinx Dashboard</title>" >< res && "acrolinx-dashboard/config/environment" >< res) {
  version = "unknown";

  req = http_get(port: port,
                 item: "/com.acrolinx.dashboard.Dashboard/com.acrolinx.dashboard.Dashboard.nocache.js");
  res = http_keepalive_send_recv(port: port, data: req);
  gwt = eregmatch(pattern: "Oc='([^']+)", string: res);
  if (!isnull(gwt[1])) {
    gwt = gwt[1];

    # newer versions have it located in /dashboard/dashboard-service where older ones are at /dashboard-service
    foreach url (make_list("/dashboard/dashboard-service", "/dashboard-service")) {
      host = report_vuln_url(port: port, url: '/com.acrolinx.dashboard.Dashboard/', url_only: TRUE);
      data = '7|0|4|' + host +
             '|F0|com.acrolinx.dashboard.client.gateway.DashboardService|getMinimalCoreServerInfo|1|2|3|4|0|';
      headers = make_array("Content-Type", "text/x-gwt-rpc; charset=utf-8",
                           "X-GWT-Permutation", gwt,
                           "X-GWT-Module-Base", host);

      req = http_post_req(port: port, url: url, data: data, add_headers: headers);
      res = http_keepalive_send_recv(port: port, data: req);

      vers = eregmatch(pattern: 'java.lang.Integer/3438268394","([0-9.]+)', string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        concUrl = url;
        break;
      }
    }
  }

  set_kb_item(name: "acrolinux/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:acrolinx:server:");
  if (!cpe)
    cpe = 'cpe:/a:acrolinx:server';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Acrolinx", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
