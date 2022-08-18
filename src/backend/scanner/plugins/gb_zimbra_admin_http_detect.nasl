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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103852");
  script_version("2022-08-17T09:34:43+0000");
  script_tag(name:"last_modification", value:"2022-08-17 09:34:43 +0000 (Wed, 17 Aug 2022)");
  script_tag(name:"creation_date", value:"2013-12-11 11:35:08 +0100 (Wed, 11 Dec 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Zimbra Admin Console Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 7071);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Admin Console of Zimbra.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 7071);

url = "/zimbraAdmin/";
install = "/zimbraAdmin";

res = http_get_cache(port: port, item: url);

if ("<title>Zimbra Administration" >< res && "appContextPath" >< res) {
  version = "unknown";

  set_kb_item(name: "zimbra/detected", value: TRUE);
  set_kb_item(name: "zimbra/admin_or_client/detected", value: TRUE);
  set_kb_item(name: "zimbra/http-admin/detected", value: TRUE);
  set_kb_item(name: "zimbra/http-admin/port", value: port);
  set_kb_item(name: "zimbra/http-admin/" + port + "/location", value: install);

  url = "/zimbraAdmin/js/zimbraMail/share/model/ZmSettings.js";
  res = http_get_cache(port: port, item: url);

  if (res !~ "^HTTP/1\.[01] 200") {
    url = "/js/zimbraMail/share/model/ZmSettings.js";
    res = http_get_cache(port: port, item: url);
  }

  # this.registerSetting("CLIENT_VERSION", {type:ZmSetting.T_CONFIG, defaultValue:"8.8.15_GA_4372"});
  vers = eregmatch(pattern: '"CLIENT_VERSION",\\s*\\{type:ZmSetting.T_CONFIG,\\s*defaultValue:"([0-9.]+)[^"]+"',
                   string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "zimbra/http-admin/" + port + "/concluded", value: vers[0]);
    set_kb_item(name: "zimbra/http-admin/" + port + "/concludedUrl",
                value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
  }

  set_kb_item(name: "zimbra/http-admin/" + port + "/version", value: version);
}

exit(0);
