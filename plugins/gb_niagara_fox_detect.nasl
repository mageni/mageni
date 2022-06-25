###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_niagara_fox_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Niagara Fox Protocol Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140278");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-08-07 10:20:07 +0700 (Mon, 07 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Niagara Fox Protocol Detection");

  script_tag(name:"summary", value:"A Niagara Fox Service is running at this host.

The Fox protocol, developed as part of the Niagara framework from Tridium, is most commonly used in building
automation systems.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(1911);

  script_xref(name:"URL", value:"https://www.tridium.com");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = 1911;

if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

query = 'fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\n};;\n';

send(socket: soc, data: query);
res = recv(socket: soc, length: 1024);
close(soc);

if (res !~ "^fox a 0")
  exit(0);

set_kb_item(name: "niagara_fox/detected", value: TRUE);
set_kb_item(name: "tridium_niagara/detected", value: TRUE);

# split the response into lines (separator is 0x0a)
pos = 0;
j = 0;
for (i=0; i<strlen(res); i++) {
  if (hexstr(res[i]) == "0a") {
    lines[j] = substr(res, pos, i-1);
    pos = i+1;
    j++;
  }
}

foreach line (lines) {
  buf = eregmatch(pattern: "fox.version=s:(.*)", string: line);
  if (!isnull(buf[1])) {
    fox_version = buf[1];
    continue;
  }

  buf = eregmatch(pattern: "hostName=s:(.*)", string: line);
  if (!isnull(buf[1])) {
    host_name = buf[1];
    continue;
  }

  buf = eregmatch(pattern: "hostAddress=s:(.*)", string: line);
  if (!isnull(buf[1])) {
    host_addr = buf[1];
    continue;
  }

  buf = eregmatch(pattern: "app\.name=s:(.*)", string: line);
  if (!isnull(buf[1])) {
    app_name = buf[1];
    set_kb_item(name: "niagara_fox/app_name", value: app_name);
    continue;
  }

  buf = eregmatch(pattern: "app\.version=s:(.*)", string: line);
  if (!isnull(buf[1])) {
    app_version = buf[1];
    set_kb_item(name: "niagara_fox/app_version", value: app_version);
    continue;
  }

  buf = eregmatch(pattern: "vm\.name=s:(.*)", string: line);
  if (!isnull(buf[1])) {
    vm_name = buf[1];
    continue;
  }

  buf = eregmatch(pattern: "vm\.version=s:(.*)", string: line);
  if (!isnull(buf[1])) {
    vm_version = buf[1];
    continue;
  }

  buf = eregmatch(pattern: "os\.name=s:(.*)", string: line);
  if (!isnull(buf[1])) {
    os_name = buf[1];
    set_kb_item(name: "niagara_fox/os_name", value: os_name);
    continue;
  }

  buf = eregmatch(pattern: "os\.version=s:(.*)", string: line);
  if (!isnull(buf[1])) {
    os_version = buf[1];
    set_kb_item(name: "niagara_fox/app_version", value: os_version);
    continue;
  }

  buf = eregmatch(pattern: "station\.name=s:(.*)", string: line);
  if (!isnull(buf[1])) {
    station_name = buf[1];
    continue;
  }

  buf = eregmatch(pattern: "hostId=s:(.*)", string: line);
  if (!isnull(buf[1])) {
    hostId = buf[1];
    continue;
  }

  buf = eregmatch(pattern: "brandId=s:(.*)", string: line);
  if (!isnull(buf[1])) {
    brandId = buf[1];
    set_kb_item(name: "niagara_fox/brandId", value: brandId);
    continue;
  }
}

register_service(port: port, proto: "niagara-fox");

report = "A Niagara Fox service is running at this port.\n\nThe following information was extrated:\n\n";

if (fox_version)
  report += "Fox Version:           " + fox_version + "\n";
if (host_name)
  report += "Host Name:             " + host_name + "\n";
if (host_addr)
  report += "Host Address:          " + host_addr + "\n";
if (app_name)
  report += "Application Name:      " + app_name + "\n";
if (app_version)
  report += "Application Version:   " + app_version + "\n";
if (vm_name)
  report += "VM Name:               " + vm_name + "\n";
if (vm_version)
  report += "VM Version:            " + vm_version + "\n";
if (os_name)
  report += "OS Name:               " + os_name + "\n";
if (os_version)
  report += "OS Version:            " + os_version + "\n";
if (station_name)
  report += "Station Name:          " + station_name + "\n";
if (hostId)
  report += "Host ID:               " + hostId + "\n";
if (brandId)
  report += "Brand ID:              " + brandId;

log_message(port: port, data: report);

exit(0);