###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_hmi_snmp_detect.nasl 12659 2018-12-05 09:26:36Z cfischer $
#
# Siemens SIMATIC HMI Device Detection (SNMP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.141682");
  script_version("$Revision: 12659 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 10:26:36 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-11-14 13:52:50 +0700 (Wed, 14 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SIMATIC HMI Device Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Siemens SIMATIC HMI devices.");

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

# Siemens, SIMATIC HMI, TP900 Comfort, 6AV2 124-0JC01-0AX0, HW: 0, SW: V 13 0 1
# Siemens, SIMATIC HMI, KTP600 Basic Mono PN, 6AV6647-0AB11-3AX0, HW:1, FW:V01.06.00
# Siemens, SIMATIC HMI, MP377, 6AV6 644-0AA01-2AX0, HW: 0, SW: V 1 0 4
if ("Siemens, SIMATIC HMI" >< sysdesc) {
  set_kb_item(name: 'simatic_hmi/detected', value: TRUE);
  set_kb_item(name: "simatic_hmi/snmp/detected", value: TRUE);
  set_kb_item(name: 'simatic_hmi/snmp/port', value: port);
  set_kb_item(name: 'simatic_hmi/snmp/' + port + '/concluded', value: sysdesc );

  sp = split(sysdesc, sep: ",", keep: FALSE);

  # Model
  if (!isnull(sp[2])) {
    model = eregmatch(pattern: "^ ([^ ]+ ?(Basic|Comfort)?)", string: sp[2]);
    if (!isnull(model[1]))
      set_kb_item(name: 'simatic_hmi/snmp/' + port + '/model', value: model[1]);
  }

  # Version
  if (!isnull(sp[5])) {
    version = eregmatch(pattern: "SW: V ([0-9 ]+)", string: sp[5]);
    if (!isnull(version[1])) {
      version = str_replace(string: version[1], find: " ", replace: ".");
      set_kb_item(name: 'simatic_hmi/snmp/' + port + '/fw_version', value: version);
    }
    else {
      version = eregmatch(pattern: "FW:V([0-9.]+)", string: sp[5]);
      if (!isnull(version[1]))
        set_kb_item(name: 'simatic_hmi/snmp/' + port + '/fw_version', value: version[1]);
    }
  }

  # HW Version
  if (!isnull(sp[4])) {
    hw = eregmatch(pattern: "HW:( )?([0-9]+)", string: sp[4]);
    if (!isnull(hw[2]))
      set_kb_item(name: 'simatic_hmi/snmp/' + port + '/hw_version', value: hw[2]);
  }
}

exit(0);
