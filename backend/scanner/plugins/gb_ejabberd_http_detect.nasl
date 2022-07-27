# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.144096");
  script_version("2020-06-09T09:51:17+0000");
  script_tag(name:"last_modification", value:"2020-06-10 10:58:50 +0000 (Wed, 10 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-09 08:32:21 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ejabberd Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of ejabberd.

  HTTP based detection of ejabberd.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 5280);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = http_get_port(default: 5280);

url = "/admin/doc/README.txt";

res = http_get_cache(port: port, item: url);

if (("Release Notes" >< res && "ejabberd" >< res) ||
    (res =~ "^HTTP/1\.[01] 401" && 'WWW-Authenticate: basic realm="ejabberd"' >< res)) {
  version = "unknown";

  set_kb_item(name: "ejabberd/detected", value: TRUE);
  set_kb_item(name: "ejabberd/http/port", value: port);

  ver = eregmatch(string: res, pattern: "ejabberd ([0-9.]+)",icase:TRUE);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "ejabberd/http/" + port + "/concluded", value: vers[0]);
    set_kb_item(name: "ejabberd/http/" + port + "/concludedUrl", value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
  }

  set_kb_item(name: "ejabberd/http/" + port + "/version", value: version);
}

exit(0);
