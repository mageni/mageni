# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.143705");
  script_version("2020-04-15T09:17:37+0000");
  script_tag(name:"last_modification", value:"2020-04-16 10:29:54 +0000 (Thu, 16 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-15 08:08:34 +0000 (Wed, 15 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Grandstream GXP IP Phones Detection (SIP)");

  script_tag(name:"summary", value:"Detection of Grandstream GXP IP Phones.

  This script performs a SIP based detection of Grandstream GXP IP Phones.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("sip_detection.nasl");
  script_mandatory_keys("sip/banner/available");

  exit(0);
}

include("host_details.inc");
include("sip.inc");
include("misc_func.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos["port"];
proto = infos["proto"];

banner = sip_get_banner(port: port, proto: proto);

# User-Agent: Grandstream GXP1400 1.0.5.15
if (banner && "Grandstream GXP"  >< banner) {
  set_kb_item(name: "grandstream/gxp/detected", value: TRUE);
  set_kb_item(name: "grandstream/gxp/sip/port", value: port);
  set_kb_item(name: "grandstream/gxp/sip/" + port + "/proto", value: proto);
  set_kb_item(name: "grandstream/gxp/sip/" + port + "/concluded", value: banner);

  model = "unknown";
  version = "unknown";

  vers = eregmatch(pattern: "(GXP[0-9]+)( ([0-9.]+))?", string: banner);
  if (!isnull(vers[1]))
    model = vers[1];

  if (!isnull(vers[2]))
    version  = vers[3];

  set_kb_item(name: "grandstream/gxp/sip/" + port + "/model", value: model);
  set_kb_item(name: "grandstream/gxp/sip/" + port + "/version", value: version);
}

exit(0);
