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
  script_oid("1.3.6.1.4.1.25623.1.0.141670");
  script_version("2022-08-09T08:58:50+0000");
  script_tag(name:"last_modification", value:"2022-08-09 08:58:50 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2018-11-12 15:24:08 +0700 (Mon, 12 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Veritas NetBackup Appliance Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Veritas NetBackup Appliance.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.veritas.com/product/backup-and-recovery/netbackup-appliances");
  script_xref(name:"URL", value:"https://www.veritas.com/support/en_US/doc/75895731-149112910-0/index");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("os_func.inc");

port = http_get_port(default: 443);
url = "/appliance/";
res = http_get_cache(port: port, item: url);

if ("Veritas NetBackup Web Management Console" >< res && "SubmitLogin.action" >< res) {
  version = "unknown";

  concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  # nb: For some versions there are also maintenance releases like eg.
  # <span>Version 3.2 Maintenance Release 3
  vers = eregmatch(pattern: "<span>Version ([0-9.]+)( Maintenance Release ([0-9]+))?", string: res);

  if (!isnull(vers[1])) {
    version = vers[1];
    cpe_version = vers[1];

    if (!isnull(vers[2])) {
      version += vers[2];
      cpe_version += ":maintenance_release" + vers[3];
    }
  }

  set_kb_item(name: "veritas/netbackup_appliance/detected", value: TRUE);
  set_kb_item(name: "veritas/netbackup_appliance/http/detected", value: TRUE);

  os_register_and_report(os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", runs_key: "unixoide",
                         desc: "Veritas NetBackup Appliance Detection (HTTP)");

  cpe = build_cpe(value: cpe_version, exp: "^([0-9.]+):?([a-z_0-9]+)?", base: "cpe:/a:veritas:netbackup_appliance:");
  if (!cpe)
    cpe = "cpe:/a:veritas:netbackup_appliance";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Veritas NetBackup Appliance", version: version,
                                           install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
