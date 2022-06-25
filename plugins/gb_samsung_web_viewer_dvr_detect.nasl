###############################################################################
# OpenVAS Vulnerability Test
#
# Samsung Web Viewer DVR Remote Detection
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114046");
  script_version("2019-05-07T14:29:24+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-07 14:29:24 +0000 (Tue, 07 May 2019)");
  script_tag(name:"creation_date", value:"2018-11-12 19:06:20 +0100 (Mon, 12 Nov 2018)");
  script_name("Samsung Web Viewer DVR Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installation of Samsung Web Viewer DVR.

  This script sends HTTP GET request and try to ensure the presence of
  Samsung Web Viewer DVR.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = "/js/language_webviewer.js";
res = http_get_cache(port: port, item: url);
if(res =~ "<h1>404\s*-\s*Not Found</h1>") {
  url = "/cgi-bin/webviewer_login_page?lang=en&loginvalue=0&port=0";
  res = http_get_cache(port: port, item: url);
}

if(res =~ '\\[\\s*"Web Viewer for Samsung DVR' || ('/language_webviewer.js"></script>' >< res && "function setcookie(){" >< res)) {

  version = "unknown";

  set_kb_item(name: "samsung/web_viewer/dvr/detected", value: TRUE);
  set_kb_item(name: "samsung/web_viewer/dvr/" + port + "/detected", value: TRUE);

  cpe = "cpe:/a:samsung:web_viewer_dvr:";

  conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "Samsung Web Viewer DVR",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: "/",
                          regPort: port,
                          regService: "www",
                          conclUrl: conclUrl);
}

exit(0);
