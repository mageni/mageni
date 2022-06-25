###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bmc_network_automation_detect.nasl 12951 2019-01-07 04:54:14Z ckuersteiner $
#
# BMC Network Automation Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141829");
  script_version("$Revision: 12951 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-07 05:54:14 +0100 (Mon, 07 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-07 11:04:28 +0700 (Mon, 07 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("BMC Network Automation Detection");

  script_tag(name:"summary", value:"Detection of BMC Network Automation

The script sends a HTTP connection request to the server and attempts to detect BMC Network Automation and
to extract its version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.bmc.com/it-solutions/truesight-network-automation.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/bca-networks/main/displayTop.do");

if (res =~ "(BMC|TrueSight) Network Automation" && "powered by bmc" >< res) {
  version = "unknown";

  # <p>Version 8.9.04</p>
  vers = eregmatch(pattern: "<p>Version ([0-9.]+)</p>", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "bmc_network_automation/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:bmc:network_automation:");
  if (!cpe)
    cpe = 'cpe:/a:bmc:network_automation';

  log_message(data: build_detection_report(app: "BMC Network Automation", version: version, install: "/",
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
