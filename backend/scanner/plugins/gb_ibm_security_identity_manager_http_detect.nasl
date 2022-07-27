# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108817");
  script_version("2020-07-08T10:06:00+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-07-08 14:19:02 +0000 (Wed, 08 Jul 2020)");
  script_tag(name:"creation_date", value:"2018-06-12 17:05:24 +0530 (Tue, 12 Jun 2018)");
  script_name("IBM Security Identity Manager Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443, 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the IBM Security Identity Manager.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = http_get_port(default: 443);

url  = "/itim/self/jsp/logon/login.jsp";
res  = http_get_cache(item: url, port: port);
url2 = "/login";
res2 = http_get_cache(item: url2, port: port);

if ("<title>IBM Security Identity Manager</title>" >< res || 'alt="IBM Security Identity Manager' >< res || 'title="IBM Security Identity Manager' >< res) {
  found = TRUE;
  conclurl = http_report_vuln_url(url: url, port: port, url_only: TRUE);
} else if ("<title>IBM Security Identity Manager</title>" >< res2 || 'alt="IBM Security Identity Manager' >< res2 || 'title="IBM Security Identity Manager' >< res2) {
  found = TRUE;
  conclurl = http_report_vuln_url(url: url2, port: port, url_only: TRUE);
}

if (found) {
  version = "unknown";
  install = "/";

  set_kb_item(name: "ibm/security_identity_manager/detected", value: TRUE);
  set_kb_item(name: "ibm/security_identity_manager/http/detected", value: TRUE);
  set_kb_item(name: "ibm/security_identity_manager/http/port", value: port);

  # IBM Security Identity Manager v7.0.1.7
  #
  # nb: The pattern above wasn't included in 7.0.1.11 release. Instead it contained something like:
  #
  # cacheBust: "7.0.1.11",
  #
  # in the same release the version was also included here:
  #
  # <script type="text/javascript" src="/javascripts/dojo/dojo/dojo.js?7.0.1.11" charset="utf-8"></script>
  #
  # nb: note that at least 6.0 didn't included the full version:
  #
  # alt="IBM Security Identity Manager v6.0" title="IBM Security Identity Manager v6.0"
  #
  vers = eregmatch(pattern: "IBM Security Identity Manager v([0-9.]+)", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  if (version == "unknown") {
    vers = eregmatch(pattern: "IBM Security Identity Manager v([0-9.]+)", string: res2);
    if (!isnull(vers[1]))
      version = vers[1];
  }

  if (version == "unknown") {
    vers = eregmatch(pattern: 'cacheBust: "([0-9.]+)"', string: res2);
    if (!isnull(vers[1]))
      version = vers[1];
  }

  set_kb_item(name: "ibm/security_identity_manager/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + vers[0] + "#---#" + conclurl );
}

exit(0);
