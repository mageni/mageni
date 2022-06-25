# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.142676");
  script_version("2019-07-30T10:17:20+0000");
  script_tag(name:"last_modification", value:"2019-07-30 10:17:20 +0000 (Tue, 30 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-30 08:39:44 +0000 (Tue, 30 Jul 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("AVM FRITZ!WLAN Repeater Detection (UPnP)");

  script_tag(name:"summary", value:"Detection of AVM FRITZ!WLAN Repeater.

  This script performs UPnP based detection of AVM FRITZ!WLAN Repeater.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_upnp_detect.nasl");
  script_mandatory_keys("upnp/identified");

  exit(0);
}

include("misc_func.inc");

port = get_port_for_service(default: 1900, ipproto: "udp", proto: "upnp");

banner = get_kb_item("upnp/" + port + "/server");

if ("AVM FRITZ!WLAN Repeater" >< banner) {
  set_kb_item(name: "avm_fritz_wlanrepeater/detected", value: TRUE);
  set_kb_item(name: "avm_fritz_wlanrepeater/upnp/detected", value: TRUE);
  set_kb_item(name: "avm_fritz_wlanrepeater/upnp/port", value: port);
  replace_kb_item(name: "avm_fritz_wlanrepeater/upnp/" + port + "/concluded", value: banner);

  model = "unknown";
  fw_version = "unknown";

  # SERVER: Living-Room UPnP/1.0 AVM FRITZ!WLAN Repeater 1750E 134.07.01
  # SERVER: FRITZ!Repeater 3000 UPnP/1.0 AVM FRITZ!Repeater 3000 174.07.04
  search = eregmatch(pattern: "AVM FRITZ!(WLAN )?Repeater ([0-9A-Z]+) ([0-9.]+)", string: banner);
  if (!isnull(search[2]))
    model = search[2];

  if (!isnull(search[3]))
    fw_version = search[3];

  set_kb_item(name: "avm_fritz_wlanrepeater/upnp/" + port + "/model", value: model);
  set_kb_item(name: "avm_fritz_wlanrepeater/upnp/" + port + "/fw_version", value: fw_version);
}

exit(0);
