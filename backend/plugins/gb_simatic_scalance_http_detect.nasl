# Copyright (C) 2013 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103722");
  script_version("2021-04-28T11:39:57+0000");
  script_tag(name:"last_modification", value:"2021-04-29 10:46:31 +0000 (Thu, 29 Apr 2021)");
  script_tag(name:"creation_date", value:"2013-05-30 16:44:04 +0200 (Thu, 30 May 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SIMATIC SCALANCE Detection (HTTP");

  script_tag(name:"summary", value:"HTTP based detection of Siemens SIMATIC SCALANCE devices.");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

res1 = http_get_cache(port: port, item: "/");
url = "/main.mwp?op=2";
res2 = http_get_cache(port: port, item: url);

if ("<title>Logon to SCALANCE" >< res1 || 'Digest realm="SCALANCE ' >< res1 ||
    ('deviceType="SCALANCE ' >< res2 && "The WEB Management requires" >< res1)) {
  model = "unknown";
  fw_version = "unknown";
  hw_version = "unknown";

  set_kb_item(name: "siemens/simatic/scalance/detected", value: TRUE);
  set_kb_item(name: "siemens/simatic/scalance/http/detected", value: TRUE);
  set_kb_item(name: "siemens/simatic/scalance/http/port", value: port);

  # var deviceType="SCALANCE M874-3";
  mod = eregmatch(pattern: 'deviceType="SCALANCE ([^"]+)"', string: res2);
  if (!isnull(mod[1])) {
    model = mod[1];
    set_kb_item(name: "siemens/simatic/scalance/http/" + port + "/concluded", value: mod[0]);
    set_kb_item(name: "siemens/simatic/scalance/http/" + port + "/concludedUrl",
                value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
  }

  set_kb_item(name: "siemens/simatic/scalance/http/" + port + "/model", value: model);
  set_kb_item(name: "siemens/simatic/scalance/http/" + port + "/fw_version", value: fw_version);
  set_kb_item(name: "siemens/simatic/scalance/http/" + port + "/hw_version", value: hw_version);
}

exit(0);
