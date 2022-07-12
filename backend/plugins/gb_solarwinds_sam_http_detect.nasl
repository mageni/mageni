# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105964");
  script_version("2022-01-12T12:55:48+0000");
  script_tag(name:"last_modification", value:"2022-01-13 11:12:56 +0000 (Thu, 13 Jan 2022)");
  script_tag(name:"creation_date", value:"2015-03-06 15:16:10 +0700 (Fri, 06 Mar 2015)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SolarWinds Server & Application Monitor (SAM) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8787);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of SolarWinds Server & Application Monitor
  (SAM).");

  script_xref(name:"URL", value:"https://www.solarwinds.com/server-application-monitor");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default: 8787);

if (!http_can_host_asp(port: port))
  exit(0);

dir = "/Orion";
url = dir + "/Login.aspx";
buf = http_get_cache(item: url, port: port);
if (!buf || buf !~ "^HTTP/1\.[01] 200")
  exit(0);

if (("SolarWinds Platform" >< buf || "SolarWinds Orion" >< buf || "Orion Platform" >< buf) &&
     ", SAM" >< buf) {

  version = "unknown";

  # </a>Orion Platform 2017.3.5 SP5, IPAM 4.6.0, CloudMonitoring 2.0.0, NPM 12.2, DPAIM 11.1.0, QoE 2.4, NTA 4.2.3, VMAN 8.2.0, SAM 6.6.0, NetPath 1.1.2 &copy; 1999-2022 SolarWinds Worldwide, LLC. All Rights Reserved.</div>
  vers = eregmatch(string: buf, pattern: ">[^<]+ SAM ([0-9.]+)[^>]+>", icase: FALSE);
  if (!isnull(vers[1])) {
    version = vers[1];
  } else {
    # Orion Platform, IPAM, NCM, NPM, DPAIM, NTA, VMAN, UDT, SAM, Toolset: 2020.2.4
    # Orion Platform HF1, IPAM, VNQM, NCM HF1, NPM, NTA HF1, SAM HF1: 2020.2.1
    vers = eregmatch(string: buf, pattern: "SAM[^:]+: ([0-9.]+)");
    if (!isnull(vers[1]))
      version = vers[1];
  }

  set_kb_item(name: "solarwinds/sam/detected", value: TRUE);
  set_kb_item(name: "solarwinds/sam/http/detected", value: TRUE);

  # nb: Only Windows is supported according to the related SAM datasheet.
  os_register_and_report(os: "Microsoft Windows", cpe:"cpe:/o:microsoft:windows", desc: "SolarWinds Server & Application Monitor (SAM) Detection (HTTP)", runs_key: "windows");

  cpe = build_cpe(value: version, exp:"^([0-9.]+)", base: "cpe:/a:solarwinds:server_and_application_monitor:");
  if (!cpe)
    cpe = "cpe:/a:solarwinds:server_and_application_monitor";

  register_product(cpe: cpe, location: dir, port: port, service: "www");

  log_message(data: build_detection_report(app: "SolarWinds Server & Application Monitor (SAM)",
                                           version: version, install: dir, cpe: cpe,
                                           concluded: vers[0]),
              port: port);
}

exit(0);
