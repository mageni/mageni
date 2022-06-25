###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_huawei_VP9660_mcu_detect.nasl 10891 2018-08-10 12:51:28Z cfischer $
#
# Huawei VP9660 Multi-Point Control Unit Detection (SNMP)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806636");
  script_version("$Revision: 10891 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:51:28 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-12-01 11:03:03 +0530 (Tue, 01 Dec 2015)");
  script_name("Huawei VP9660 Multi-Point Control Unit Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection
  of Huawei VP9660 Multi-Point Control Unit");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");
include("snmp_func.inc");

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);
if(!sysdesc) exit(0);

if("HUAWEI VP9660" >!< sysdesc ) exit( 0 );

version = eregmatch( pattern:'HUAWEI VP9660 ([A-Z0-9a-z]+) ', string:sysdesc);
if(isnull(version[1])){
  huaVer = "Unknown";
} else {
  huaVer = version[1];
}

set_kb_item(name:"huawei/mcu/installed", value:TRUE);
set_kb_item(name:"huawei/mcu/version/snmp", value:huaVer);

cpe = build_cpe(value:huaVer, exp:"([0-9A-Za-z]+)", base:"cpe:/o:huawei:vp_9660_firmware:");
if(!cpe)
  cpe = "cpe:/o:huawei:vp_9660_firmware:";

register_product(cpe:cpe, location:port + "/udp", port:port, proto:"udp", service:"snmp");

log_message(data:build_detection_report( app:"HUAWEI VP9660 MCU",
                                           version:huaVer,
                                           install:port + "/udp",
                                           cpe:cpe,
                                           concluded:sysdesc),
                                           port:port,
                                           proto:"udp");
exit(0);
