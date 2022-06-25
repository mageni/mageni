# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106078");
  script_version("2022-03-03T07:27:01+0000");
  script_tag(name:"last_modification", value:"2022-03-03 11:27:55 +0000 (Thu, 03 Mar 2022)");
  script_tag(name:"creation_date", value:"2016-05-20 11:10:26 +0700 (Fri, 20 May 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WatchGuard Firebox Appliance Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of WatchGuard Firebox appliances.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
#include("os_func.inc");

port = http_get_port(default: 8080);

url = "/";
res = http_get_cache(port: port, item: url);

if (">The <b>Fireware XTM Web UI from WatchGuard</b>" >!< res &&
    "<title>Fireware XTM User Authentication</title>" >!< res &&
    # Two examples:
    # var newloc = "/wgcgi.cgi?action=sslvpn_web_logon&fw_logon_type=status";
    # var newloc = "/wgcgi.cgi?action=fw_logon&fw_logon_type=status";
    res !~ "/wgcgi\.cgi\?action=(fw|sslvpn_web)_logon") {
  url = "/auth/login";

  res = http_get_cache(port: port, item: url);

  if (">Powered by WatchGuard Technologies<" >!< res &&
      # nb: The following two are from the Access Portal:
      # https://www.watchguard.com/help/docs/help-center/en-US/Content/en-US/Fireware/services/access%20portal/access_portal_about.html
      res !~ "<div>Copyright [^<]+ WatchGuard Technologies, Inc\. All rights reserved\.</div>" &&
      "background-image: url('/images/watchguard/logo.svg');" >!< res)
    exit(0);
}

model = "unknown";
version = "unknown";

set_kb_item(name: "watchguard/firebox/detected", value: TRUE);
set_kb_item(name: "watchguard/firebox/http/detected", value: TRUE);
set_kb_item(name: "watchguard/firebox/http/port", value: port);
set_kb_item(name: "watchguard/firebox/http/" + port + "/concludedUrl",
            value: http_report_vuln_url(port: port, url: url, url_only: TRUE));

if ("Fireware XTM" >< res)
  model = "Fireware XTM";
else {
  req = http_get(port: port, item: "/js/xtm-webui.js");
  res = http_keepalive_send_recv(port: port, data: req);

  if (res =~ "^HTTP/1\.[01] 200" && "var WGRD = " >< res)
    model = "Fireware XTM";
}

set_kb_item(name: "watchguard/firebox/http/" + port + "/model", value: model);
set_kb_item(name: "watchguard/firebox/http/" + port + "/version", value: version);

exit(0);
