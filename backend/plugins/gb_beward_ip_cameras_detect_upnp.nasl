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
  script_oid("1.3.6.1.4.1.25623.1.0.114074");
  script_version("$Revision: 13890 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 16:36:04 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-19 14:54:11 +0100 (Tue, 19 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Beward IP Camera Detection(UPNP)");

  script_tag(name:"summary", value:"Detection of Beward IP cameras via the UPNP banner.

  The script sends a connection request to the server and attempts to detect the UPNP banner for the Beward IP camera.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_upnp_detect.nasl");
  script_mandatory_keys("upnp/identified");

  script_xref(name:"URL", value:"https://www.beward.net/category/10");

  exit(0);
}

include("misc_func.inc");

port = get_port_for_service(default: 1900, ipproto: "udp", proto: "upnp");
banner = get_kb_item("upnp/" + port + "/banner");

#DEVICE-INFO: Beward/N100/M2.1.6.04C014/169.254.5.164
if(banner && egrep(pattern: "DEVICE-INFO:\s*Beward", string: banner, icase:TRUE)) {

  model = "unknown";
  version = "unknown";

  info = eregmatch(pattern: "DEVICE-INFO:\s*Beward/([^/]+)/([^/]+)/", string: banner);
  if(info) {

    if(!isnull(info[1]))
      model = info[1];

    if(!isnull(info[2]))
      version = info[2];

    set_kb_item(name: "beward/ip_camera/upnp/" + port + "/concluded", value: info[0]);
  }

  set_kb_item(name: "beward/ip_camera/detected", value: TRUE);
  set_kb_item(name: "beward/ip_camera/upnp/detected", value: TRUE);
  set_kb_item(name: "beward/ip_camera/upnp/port", value: port);

  set_kb_item(name:"beward/ip_camera/upnp/" + port + "/model", value: model);
  set_kb_item(name:"beward/ip_camera/upnp/" + port + "/version", value: version);
}

exit(0);