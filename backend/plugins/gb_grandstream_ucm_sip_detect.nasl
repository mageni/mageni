##############################################################################
# OpenVAS Vulnerability Test
#
# Grandstream UCM Series IP PBX Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106324");
  script_version("2020-03-24T10:03:24+0000");
  script_tag(name:"last_modification", value:"2020-03-25 11:04:45 +0000 (Wed, 25 Mar 2020)");
  script_tag(name:"creation_date", value:"2016-10-04 13:39:10 +0700 (Tue, 04 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Grandstream UCM Series IP PBX Detection (SIP)");

  script_tag(name:"summary", value:"Detection of Grandstream UCM Series IP PBX.

  This script performs a SIP based detection of Grandstream UCM devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

# Server: Grandstream UCM6102V1.6A 1.0.14.21
if (banner && "Grandstream UCM" >< banner) {
  set_kb_item(name: "grandstream/ucm/detected", value: TRUE);
  set_kb_item(name: "grandstream/ucm/sip/port", value: port);
  set_kb_item(name: "grandstream/ucm/sip/" + port + "/proto", value: proto);
  set_kb_item(name: "grandstream/ucm/sip/" + port + "/concluded", value: banner);

  model = "unknown";
  version = "unknown";

  mo = eregmatch(pattern: "(UCM[0-9]+)", string: banner);
  if (!isnull(mo[1]))
    model = mo[1];

  vers = eregmatch(pattern: "UCM.* ([0-9.]+)", string: banner);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "grandstream/ucm/sip/" + port + "/model", value: model);
  set_kb_item(name: "grandstream/ucm/sip/" + port + "/version", value: version);
}

exit(0);
