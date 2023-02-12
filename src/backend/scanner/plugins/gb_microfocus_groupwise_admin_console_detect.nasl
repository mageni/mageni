# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105077");
  script_version("2023-01-31T10:08:41+0000");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"creation_date", value:"2014-09-03 15:08:39 +0200 (Wed, 03 Sep 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Micro Focus / Novell GroupWise Detection (Administration Console)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9710);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based Micro Focus / Novell GroupWise Administration
  Console.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 9710);

url = "/gwadmin-console/login.jsp";

res = http_get_cache(port: port, item: url);

if ("<title>GroupWise Administration Console</title>" >< res && "username_ui" >< res) {
  version = "unknown";

  set_kb_item(name: "microfocus/groupwise/detected", value: TRUE);
  set_kb_item(name: "microfocus/groupwise/admin_console/detected", value: TRUE);
  set_kb_item(name: "microfocus/groupwise/admin_console/port", value: port);
  set_kb_item(name: "microfocus/groupwise/admin_console/" + port + "/concludedUrl",
              value: http_report_vuln_url(port: port, url: url, url_only: TRUE));

  set_kb_item(name: "microfocus/groupwise/admin_console/" + port + "/version", value: version);
}

exit( 0 );
