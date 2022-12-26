# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.149043");
  script_version("2022-12-22T11:46:57+0000");
  script_tag(name:"last_modification", value:"2022-12-22 11:46:57 +0000 (Thu, 22 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-22 04:44:28 +0000 (Thu, 22 Dec 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Gunicorn Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("gunicorn/banner");

  script_tag(name:"summary", value:"HTTP based detection of the Gunicorn (Green Unicorn) HTTP
  server.");

  script_xref(name:"URL", value:"https://gunicorn.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!banner = http_get_remote_headers(port: port))
  exit(0);

if (!concl = egrep(string: banner, pattern: "^[Ss]erver\s*:\s*gunicorn", icase: FALSE))
  exit(0);

concluded = chomp(concl);
version = "unknown";
install = port + "/tcp";

# Server: gunicorn/19.8.1
# Server: gunicorn/20.0.4
vers = eregmatch(pattern: "[Ss]erver\s*:\s*gunicorn/([0-9.]+)", string: banner, icase: FALSE);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "gunicorn/detected", value: TRUE);
set_kb_item(name: "gunicorn/http/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:gunicorn:gunicorn:");
if (!cpe)
  cpe = "cpe:/a:gunicorn:gunicorn";

os_register_and_report(os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", port: port, runs_key: "unixoide",
                       desc: "Gunicorn Detection (HTTP)");

register_product(cpe: cpe, location: install, port: port, service: "www");

log_message(data: build_detection_report(app: "Gunicorn", version: version, install: install, cpe: cpe,
                                         concluded: concluded),
            port: port);

exit(0);
