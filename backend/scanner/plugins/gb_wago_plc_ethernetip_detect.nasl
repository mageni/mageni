###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wago_plc_ethernetip_detect.nasl 13974 2019-03-04 08:18:06Z ckuersteiner $
#
# WAGO PLC Detection (EtherNet/IP)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141768");
  script_version("$Revision: 13974 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-04 09:18:06 +0100 (Mon, 04 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-12-07 13:39:37 +0700 (Fri, 07 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WAGO PLC Detection (EtherNet/IP)");

  script_tag(name:"summary", value:"This script performs EtherNet/IP based detection of WAGO PLC Controllers.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_ethernetip_detect.nasl");
  script_mandatory_keys("ethernetip/detected");

  exit(0);
}

include("misc_func.inc");

prod_name = get_kb_item("ethernetip/product_name");
if (!prod_name || prod_name !~ "^WAGO 750-")
  exit(0);

port = get_port_for_service(default: 44818, proto: "ethernetip");

set_kb_item(name: 'wago_plc/detected', value: TRUE);
set_kb_item(name: "wago_plc/ethernetip/detected", value: TRUE);
set_kb_item(name: 'wago_plc/ethernetip/port', value: port);

mod = eregmatch(pattern: "WAGO (.*)", string: prod_name);
if (!isnull(mod[1]))
  set_kb_item(name: 'wago_plc/ethernetip/' + port + '/model', value: mod[1]);

if (rev = get_kb_item("ethernetip/revision"))
  set_kb_item(name: 'wago_plc/ethernetip/' + port + '/fw_version', value: rev);

exit(0);
