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
  script_oid("1.3.6.1.4.1.25623.1.0.808250");
  script_version("2022-03-29T08:25:19+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-03-29 08:25:19 +0000 (Tue, 29 Mar 2022)");
  script_tag(name:"creation_date", value:"2016-07-14 16:30:56 +0530 (Thu, 14 Jul 2016)");
  script_name("HP/HPE/Micro Focus Universal CMDB Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://software.microfocus.com/en-us/products/configuration-management-system-database/overview");

  script_tag(name:"summary", value:"HTTP based detection of HP/HPE/Micro Focus Universal CMDB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:8080);

url = "/ucmdb-ui/login_page.jsp";
res = http_get_cache(item:url, port:port);

if (res =~ "<title>(HPE? )?Universal CMDB</title>" &&
   'STATE_LOGIN_FAILS' >< res && 'User Login:' >< res) {

  install = "/";
  version = "unknown";

  # nb: On Micro Focus variants this is empty / doesn't have a version anymore.
  # <div class="version">Universal CMDB<br/>
  ver = eregmatch(pattern:'class="version">(HPE? )?Universal CMDB ([0-9.]+)', string:res);
  if (!isnull(ver[2]))
    version = ver[2];

  set_kb_item(name:"hp_microfocus/ucmdb/detected", value:TRUE);
  set_kb_item(name:"hp_microfocus/ucmdb/http/detected", value:TRUE);

  cpe1 = build_cpe(value: version, exp:"^([0-9.]+)", base:"cpe:/a:microfocus:universal_cmbd_server:");
  cpe2 = build_cpe(value: version, exp:"^([0-9.]+)", base:"cpe:/a:hp:universal_cmbd_foundation:");
  if(!cpe1) {
    cpe1 = "cpe:/a:microfocus:universal_cmbd_server";
    cpe2 = "cpe:/a:hp:universal_cmbd_foundation";
  }

  register_product(cpe:cpe1, location:install, port:port, service:"www");
  register_product(cpe:cpe2, location:install, port:port, service:"www");

  log_message(data:build_detection_report(app: "HP/HPE/Micro Focus Universal CMDB", version: version, install: install,
                                          cpe: cpe1, concluded: ver[0], concludedUrl: http_report_vuln_url(port: port, url: url, url_only: TRUE)),
              port: port);
}

exit(0);
