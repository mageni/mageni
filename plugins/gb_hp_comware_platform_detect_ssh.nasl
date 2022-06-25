###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_comware_platform_detect_ssh.nasl 13576 2019-02-11 12:44:20Z cfischer $
#
# HP Comware Devices Detect (SSH)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106411");
  script_version("$Revision: 13576 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 13:44:20 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-11-25 11:50:20 +0700 (Fri, 25 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HP Comware Devices Detect (SSH)");

  script_tag(name:"summary", value:"This script performs SSH based detection of HP Comware Devices.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/hp/comware/detected");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");

port = get_ssh_port(default:22);
banner = get_ssh_server_banner(port:port);
if (!banner || banner !~ "SSH-[0-9.]+-Comware")
  exit(0);

version = "unknown";

vers = eregmatch(pattern: "Comware-([0-9.]+)", string: banner);
if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "hp/comware_device/version", value: version);
}

set_kb_item(name: "hp/comware_device", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:hp:comware:");
if (!cpe)
  cpe = 'cpe:/a:hp:comware';

register_product(cpe: cpe, port: port, service: "ssh");

log_message(data: build_detection_report(app: "HP Comware Device", version: version, cpe: cpe, concluded: vers[0]),
            port: port);

exit(0);