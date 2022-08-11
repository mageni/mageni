###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rockwell_micrologix_http_detect.nasl 12766 2018-12-12 08:34:25Z ckuersteiner $
#
# Rockwell Automation MicroLogix Detection (HTTP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.140662");
  script_version("$Revision: 12766 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-12 09:34:25 +0100 (Wed, 12 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-01-10 10:09:48 +0700 (Wed, 10 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Rockwell Automation MicroLogix Detection (HTTP)");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Rockwell Automation MicroLogix
PLC's.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ABwww/banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

banner = get_http_banner(port: port);
if ("A-B WWW" >!< banner)
  exit(0);

url = "/home.htm";
res = http_get_cache(port: port, item: url);

if ("<title>Rockwell Automation</title>" >< res && res =~ "MicroLogix [0-9]+ Processor") {
  set_kb_item(name: "rockwell_micrologix/detected", value: TRUE);
  set_kb_item(name: "rockwell_micrologix/http/detected", value: TRUE);
  set_kb_item(name: "rockwell_micrologix/http/port", value: port);

  app = eregmatch(pattern: "MicroLogix ([0-9]+) Processor", string: res);
  device = app[1];
  app = app[0];
  version = "unknown";

  vers = eregmatch(pattern: "O(/)?S.*Revision</td><td>Series ([A-Z]) FRN ([0-9.]+)</td>", string: res);
  if (!isnull(vers[3]))
    set_kb_item(name: "rockwell_micrologix/http/" + port + "/fw_version", value: vers[3]);

  if (!isnull(vers[2]))
    set_kb_item(name: "rockwell_micrologix/http/" + port + "/series", value: vers[2]);

  dev_name = eregmatch(pattern: "Device Name</td><td>([^<]+)", string: res);
  if (!isnull(dev_name[1]))
    set_kb_item(name: "rockwell_micrologix/http/" + port + "/model", value: dev_name[1]);

  mac = eregmatch(pattern: "Ethernet Address \(MAC\)</td><td>([A-F0-9-]{17})", string: res);
  if (!isnull(mac[1])) {
    mac = str_replace(string: mac[1], find: "-", replace: ":");
    set_kb_item(name: "rockwell_micrologix/http/" + port + "/mac", value: mac);
    register_host_detail(name: "MAC", value: mac, desc: "gb_rockwell_micrologix_http_detect.nasl");
    replace_kb_item(name: "Host/mac_address", value: mac);
  }

  exit(0);
}

exit(0);
