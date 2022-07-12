###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kubernetes_dashboard_detect.nasl 11356 2018-09-12 10:46:43Z tpassfeld $
#
# Kubernetes Dashboard UI Detection
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.114009");
  script_version("$Revision: 11356 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 12:46:43 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-07-16 15:22:55 +0200 (Mon, 16 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kubernetes Dashboard UI Detection");

  script_tag(name:"summary", value:"Detection of Kubernetes Dashboard/Web UI.

  The script sends a connection request to the server and attempts to detect Kubernetes Dashboard UI and to
  extract its version if possible.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://github.com/kubernetes/dashboard");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);
res1 = http_get_cache(port: port, item: "/");
res2 = http_get_cache(port: port, item: "/api/v1/overview");

# ng-app="kubernetesDashboard">
if(egrep(pattern: "[Kk]ubernetesDashboard", string: res1) ||
    "system:serviceaccount:kube-system:kubernetes-dashboard" >< res2) {
   version = "unknown";
   install = "/";

   id = eregmatch(pattern: 'src="static/app\\.([^.]+)\\.js">', string: res1);

   if(id[1]){
      url = "/static/app." + id[1] + ".js";
      conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);

      res3 = http_get_cache(port: port, item: url);
      vers = eregmatch(pattern: 'dashboardVersion="v([0-9.]+)"', string: res3);

      if(vers[1]) version = vers[1];
   }

   set_kb_item(name: "kubernetes/dashboard/detected", value: TRUE);
   set_kb_item(name: "kubernetes/dashboard/version", value: version);
   set_kb_item(name: "kubernetes/dashboard/" + port + "/detected", value: TRUE);

   cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:kubernetes:dashboard:"); # CPE is not registered yet

   if(!cpe) cpe = 'cpe:/a:kubernetes:dashboard';

   register_product(cpe: cpe, location: install, port: port);

   log_message(data: build_detection_report(app: "Kubernetes Dashboard", version: version, install: install, cpe: cpe,
                                            concluded: vers[0], concludedUrl: conclUrl),port: port);

}

exit(0);
