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
  script_oid("1.3.6.1.4.1.25623.1.0.145487");
  script_version("2021-03-08T11:51:22+0000");
  script_tag(name:"last_modification", value:"2021-03-09 11:15:36 +0000 (Tue, 09 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-03 07:09:16 +0000 (Wed, 03 Mar 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HP / HPE Systems Insight Manager (SIM) Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of HP / HPE Systems Insight Manager (SIM).");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 50000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.hp.com");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 50000);

res = http_get_cache(port: port, item: "/");

# nb: At least in the HPE version of SIM the smartcard html text below had only a "System Insight"
# text without the "s" in "Systems" so we're checking all variants here just to be sure...
if ((res =~ "<title>HPE? Systems? Insight Manager" >< res && res =~ 'signInTitle"><h[0-9]>HPE? Systems? Insight Manager') ||
    res =~ "<li>Obtain an exported HPE? Systems? Insight Manager server certificate file from the administrator\.</li>" ||
    res =~ "<h[0-9]>Please insert your Smart Card and login to HPE? Systems? Insight Manager\.</h[0-9]></td>") {
  version = "unknown";

  set_kb_item(name: "hp/systems_insight_manager/detected", value: TRUE);
  set_kb_item(name: "hp/systems_insight_manager/http/detected", value: TRUE);

  # nb: NVD is still using this one for newer CVEs and HPE variants.
  cpe = "cpe:/a:hp:systems_insight_manager";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "HP / HPE Systems Insight Manager (SIM)", version: version, install: "/",
                                           cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
