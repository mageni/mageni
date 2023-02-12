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
  script_oid("1.3.6.1.4.1.25623.1.0.141122");
  script_version("2023-01-25T10:11:07+0000");
  script_tag(name:"last_modification", value:"2023-01-25 10:11:07 +0000 (Wed, 25 Jan 2023)");
  script_tag(name:"creation_date", value:"2018-05-30 11:14:38 +0700 (Wed, 30 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Zoho Corp. ManageEngine ADAudit Plus Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Zoho Corp. ManageEngine ADAudit Plus.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.manageengine.com/products/active-directory-audit/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8081);

res = http_get_cache(port: port, item: "/");

# nb: Usually the title is just:
# - <title>ADAudit Plus</title>
# but at least a few "live" systems had something like e.g.:
# - <title>ADAudit Plus - Somestring</title>
# - <title>Completely different string</title>
# so a second alternative pattern was added to catch these cases
if ("/ADAPLogin.js" >< res &&
     ("<title>ADAudit Plus</title>" >< res ||
      res =~ "/vendor-auditplus\.(css|js)"
     )
   ) {

  version = "unknown";
  install = "/";

  # e.g.
  # vendor-auditplus.css?v=5053
  # vendor-auditplus.js?v=5053
  # assets/common-styles-auditplus.css?v=7090
  vers = eregmatch(pattern: "\.(css|js)\?v=([0-9]+)", string: res);
  if (!isnull(vers[2]))
    version = vers[2];

  set_kb_item(name: "manageengine/products/detected", value: TRUE);
  set_kb_item(name: "manageengine/products/http/detected", value: TRUE);
  set_kb_item(name: "manageengine/adaudit_plus/detected", value: TRUE);
  set_kb_item(name: "manageengine/adaudit_plus/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9]+)", base: "cpe:/a:zohocorp:manageengine_adaudit_plus:");
  if (!cpe)
    cpe = "cpe:/a:zohocorp:manageengine_adaudit_plus";

  # Only Windows platforms supported according to:
  # https://www.manageengine.com/products/active-directory-audit/system-requirements.html#os
  os_register_and_report(os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", port: port,
                         desc: "Zoho Corp. ManageEngine ADAudit Plus Detection (HTTP)", runs_key: "windows");

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Zoho Corp. ManageEngine ADAudit Plus", version: version, install: install,
                                           cpe: cpe, concluded: vers[0]),
              port: port);
}

exit(0);
