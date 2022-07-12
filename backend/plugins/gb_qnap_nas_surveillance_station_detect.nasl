# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.145423");
  script_version("2021-02-22T04:16:37+0000");
  script_tag(name:"last_modification", value:"2021-02-22 10:44:10 +0000 (Mon, 22 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-22 03:23:10 +0000 (Mon, 22 Feb 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("QNAP QTS Surveillance Station Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of QNAP QTS Surveillance Station.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts", "qnap/port");

  script_xref(name:"URL", value:"https://www.qnap.com/en/software/surveillance-station");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

# Surveillance Station is part of QNAP QTS
if (!port = get_kb_item("qnap/port"))
  exit(0);

res = http_get_cache(port: port, item: "/cgi-bin/surveillance/index.html");

if ("<title>Surveillance Station</title>" && "NVR_SURVEILLANCE_STATION" >< res) {
  version = "unknown";

  # images_nvr/favicon.ico?5.1.5.20210205
  # images_ss/desktop.jpg?5.1.5.20210205
  # Note: 5.1.5 seems to be the main version, the rest might be some "random" number and not the full version
  #       as e.g. a full version is 5.1.5.4.3
  vers = eregmatch(pattern: "\.(ico|jpg|png|js)\?([0-9.]+)", string: res);
  if (!isnull(vers[2])) {
    version = split(vers[2], sep: ".", keep: FALSE);
    if (max_index(version) == 4)
      version = version[0] + "." + version[1] + "." + version[2];
  }

  set_kb_item(name: "qnap/surveillance/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:qnap:surveillance_station:");
  if (!cpe)
    cpe = "cpe:/a:qnap:surveillance_station";

  register_product(cpe: cpe, location: "/cgi-bin/surveillance", port: port, service: "www");

  log_message(data: build_detection_report(app: "QNAP QTS Surveillance Station", version: version,
                                           install: "/cgi-bin/surveillance", cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
