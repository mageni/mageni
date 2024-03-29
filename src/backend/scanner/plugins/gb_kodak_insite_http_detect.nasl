# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106820");
  script_version("2022-11-09T12:45:17+0000");
  script_tag(name:"last_modification", value:"2022-11-09 12:45:17 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"creation_date", value:"2017-05-22 16:58:14 +0700 (Mon, 22 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kodak InSite Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Kodak InSite.");

  script_xref(name:"URL", value:"http://www.kodak.com/US/en/prinergy-workflow/platform/insite-prepress-portal/default.htm");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/Site/Pages/login.aspx";
res = http_get_cache(port: port, item: url);

if ("Kodak InSite" >< res && "CSWStyle_PoweredBy" >< res && "kstrLoginPageURL" >< res) {
  version = "unknown";
  concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  vers = eregmatch(pattern: "&amp;Version=([0-9.]+)", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "kodak/insite/detected", value: TRUE);
  set_kb_item(name: "kodak/insite/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:kodak:insite:");
  if (!cpe)
    cpe = "cpe:/a:kodak:insite";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Kodak InSite", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
