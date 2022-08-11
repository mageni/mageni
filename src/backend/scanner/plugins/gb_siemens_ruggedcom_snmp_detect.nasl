###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_siemens_ruggedcom_snmp_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Siemens RUGGEDCOM Detection (SNMP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.140810");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-26 13:19:50 +0700 (Mon, 26 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens RUGGEDCOM Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Siemens RUGGEDCOM devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  exit(0);
}

include("snmp_func.inc");

port = get_snmp_port(default: 161);

if (!sysdesc = get_snmp_sysdesc(port: port))
  exit(0);

if ("Siemens, SIMATIC NET, RUGGEDCOM" >!< sysdesc && "RuggedCom" >!< sysdesc)
  exit(0);

set_kb_item(name: "siemens_ruggedcom/detected", value: TRUE);
set_kb_item(name: "siemens_ruggedcom/snmp/detected", value: TRUE);
set_kb_item(name: "siemens_ruggedcom/snmp/port", value: port);

# Siemens, SIMATIC NET, RUGGEDCOM RM1224 NAM, 6GK6 108-4AM00-2DA2, HW: Version 1, FW: Version V04.01.02, SVPH8159590
# RuggedCom RX1500 (this RX devices are running ROX)
prod = eregmatch(pattern: 'RUGGEDCOM ([^\r\n,]+)', string: sysdesc, icase: TRUE);
if (!isnull(prod[1]))
  set_kb_item(name: "siemens_ruggedcom/snmp/" + port + "/model", value: prod[1]);

vers = eregmatch(pattern: "FW: Version V([0-9.]+)", string: sysdesc);
if (!isnull(vers[1])) {
  set_kb_item(name: "siemens_ruggedcom/snmp/" + port + "/version", value: vers[1]);
  set_kb_item(name: "siemens_ruggedcom/snmp/" + port + "/concluded", value: vers[0]);
}
else {
  fw_oid = "1.3.6.1.4.1.15004.4.2.3.3.0";
  fw_res = snmp_get(port: port, oid: fw_oid);
  vers = eregmatch(pattern: "ROX ([0-9.]+)", string: fw_res);
  if (!isnull(vers[1])) {
    set_kb_item(name: "siemens_ruggedcom/snmp/" + port + "/version", value: vers[1]);
    set_kb_item(name: "siemens_ruggedcom/snmp/" + port + "/concluded", value: vers[0]);
    set_kb_item(name: "siemens_ruggedcom/snmp/" + port + "/concludedOID", value: fw_oid);
    set_kb_item(name: "siemens_ruggedcom/isROX", value: TRUE);
  }
}

exit(0);
