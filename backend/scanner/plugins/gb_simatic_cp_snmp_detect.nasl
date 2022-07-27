###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_cp_snmp_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Siemens SIMATIC CP Device Detection (SNMP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.140736");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-01 15:08:26 +0700 (Thu, 01 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SIMATIC CP Device Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Siemens SIMATIC CP devices.");

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

sysdesc = get_snmp_sysdesc(port: port);
if (!sysdesc)
  exit(0);

# Siemens, SIMATIC NET, CP 343-1 Lean, 6GK7 343-1CX10-0XE0, HW: Version 3, FW: Version V2.2.20, VPA2517023
if (egrep(string: sysdesc, pattern: "Siemens, SIMATIC NET, CP")) {
  set_kb_item(name: 'simatic_cp/detected', value: TRUE);
  set_kb_item(name: "simatic_cp/snmp/detected", value: TRUE);
  set_kb_item(name: 'simatic_cp/snmp/port', value: port);

  sp = split(sysdesc, sep: ",", keep: FALSE);

  # Model
  if (!isnull(sp[2])) {
    model = eregmatch(pattern: '(CP.*)', string: sp[2]);
    if (!isnull(model[1]))
      set_kb_item(name: 'simatic_cp/snmp/' + port + '/model', value: model[1]);
  }

  # Version
  if (!isnull(sp[5])) {
    version = eregmatch(pattern: "V([0-9.]+)", string: sp[5]);
    if (!isnull(version[1]))
      set_kb_item(name: 'simatic_cp/snmp/' + port + '/version', value: version[1]);
  }

  # Module
  if (!isnull(sp[3])) {
    module = eregmatch(pattern: '^ (.*)', string: sp[3]);
    set_kb_item(name: 'simatic_cp/snmp/' + port + '/module', value: module[1]);
  }

  # HW Version
  if (!isnull(sp[4])) {
    hw = eregmatch(pattern: "HW: Version ([0-9]+)", string: sp[4]);
    set_kb_item(name: 'simatic_cp/snmp/' + port + '/hw_version', value: hw[1]);
  }
}

exit(0);
