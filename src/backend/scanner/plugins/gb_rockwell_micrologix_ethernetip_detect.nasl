###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rockwell_micrologix_ethernetip_detect.nasl 12766 2018-12-12 08:34:25Z ckuersteiner $
#
# Rockwell Automation MicroLogix Detection (EtherNet/IP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.141771");
  script_version("$Revision: 12766 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-12 09:34:25 +0100 (Wed, 12 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-12 12:47:16 +0700 (Wed, 12 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Rockwell Automation MicroLogix Detection (EtherNet/IP)");

  script_tag(name:"summary", value:"Detection of Rockwell Automation MicroLogix PLC's.

This script performs EtherNet/IP based detection of Rockwell Automation MicroLogix PLC's.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_ethernetip_detect.nasl");
  script_mandatory_keys("ethernetip/detected");

  exit(0);
}

include("misc_func.inc");

vendor = get_kb_item("ethernetip/vendor");
if (!vendor || vendor !~ "^Rockwell Automation")
  exit(0);

prod_name = get_kb_item("ethernetip/product_name");
if (!prod_name || prod_name !~ "^17")
  exit(0);

port = get_port_for_service(default: 44818, ipproto: "ethernetip");

set_kb_item(name: "rockwell_micrologix/detected", value: TRUE);
set_kb_item(name: "rockwell_micrologix/ethernetip/detected", value: TRUE);
set_kb_item(name: 'rockwell_micrologix/ethernetip/port', value: port);

buf = eregmatch(pattern:"([^ ]+) ([A-Z])/([0-9.]+)", string: prod_name);
if (!isnull(buf[1]))
  set_kb_item(name: 'rockwell_micrologix/ethernetip/' + port + '/model', value: buf[1]);

if (!isnull(buf[2]))
  set_kb_item(name: 'rockwell_micrologix/ethernetip/' + port + '/series', value: buf[2]);

if (!isnull(buf[3]))
  set_kb_item(name: 'rockwell_micrologix/ethernetip/' + port + '/fw_version', value: buf[3]);

exit(0);
