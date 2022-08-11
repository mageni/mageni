###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_siemens_ruggedcom_telnet_detect.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# Siemens RUGGEDCOM Detection (Telnet)
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
  script_oid("1.3.6.1.4.1.25623.1.0.140808");
  script_version("$Revision: 13624 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-02-26 11:52:48 +0700 (Mon, 26 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens RUGGEDCOM Detection (Telnet)");

  script_tag(name:"summary", value:"Detection of Siemens RUGGEDCOM.

The script sends a telnet connection request to the device and attempts to detect the presence of devices running
RUGGEDCOM and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/siemens/ruggedcom/detected");

  exit(0);
}

include("host_details.inc");
include("telnet_func.inc");

port = get_telnet_port(default: 23);
banner = get_telnet_banner(port: port);
if (!banner)
  exit(0);

if ("Rugged Operating System" >< banner || "Command Line Interface RUGGEDCOM" >< banner) {

  version = "unknown";

  set_kb_item(name: "siemens_ruggedcom/detected", value: TRUE);
  set_kb_item(name: "siemens_ruggedcom/telnet/detected", value: TRUE);
  set_kb_item(name: "siemens_ruggedcom/telnet/port", value: port);

  # Rugged Operating System v3.8.3 (Nov 30 2010 16:36)
  vers = eregmatch(pattern: "Rugged Operating System v([0-9.]+)", string: banner);
  if (!isnull(vers[1])) {
    set_kb_item(name: "siemens_ruggedcom/telnet/" + port + "/version", value: vers[1]);
    set_kb_item(name: "siemens_ruggedcom/telnet/" + port + "/concluded", value: vers[0]);
  }

  # Product:        RS900-HI-D-C2-C2-00
  prod = eregmatch(pattern: 'Product:        ([^\n\r]+)', string: banner);
  if (!isnull(prod[1]))
    set_kb_item(name: "siemens_ruggedcom/telnet/" + port + "/model", value: prod[1]);
  else
   # Command Line Interface RUGGEDCOM RM1200
   prod = eregmatch(pattern: 'Interface RUGGEDCOM ([^\r\n]+)', string: banner);
   if (!isnull(prod[1]))
     set_kb_item(name: "siemens_ruggedcom/telnet/" + port + "/model", value: prod[1]);

  mac = eregmatch(pattern: "MAC Address:    ([A-F0-9-]{17})", string: banner);
  if (!isnull(mac[1])) {
    mac = str_replace( string: mac[1], find: "-", replace: ":");
    register_host_detail(name: "MAC", value: mac[1], desc: "gb_siemens_ruggedcom_telnet_detect.nasl");
    replace_kb_item(name: "Host/mac_address", value: mac[1]);
    set_kb_item(name: "siemens_ruggedcom/telnet/" + port + "/mac", value: mac);
  }
}

exit(0);