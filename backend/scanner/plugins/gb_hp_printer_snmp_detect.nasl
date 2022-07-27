# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147612");
  script_version("2022-02-09T07:42:31+0000");
  script_tag(name:"last_modification", value:"2022-02-17 11:13:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-08 07:24:16 +0000 (Tue, 08 Feb 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HP Printer Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of HP printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdescr_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("snmp_func.inc");
include("misc_func.inc");
include("dump.inc");

port = snmp_get_port(default: 161);

sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc)
  exit(0);

# HP ETHERNET MULTI-ENVIRONMENT,SN:CNBRP2T30V,FN:57467TK,SVCID:31114,PID:HP Neverstop Laser MFP 1200w
# HP ETHERNET MULTI-ENVIRONMENT,SN:CNB8H31B0L,FN:WV220DS,SVCID:25140,PID:HP LaserJet Pro MFP M225dw
# HP ETHERNET MULTI-ENVIRONMENT,SN:VNH4G03975,FN:3F40CJS,SVCID:10355,PID:Inspire Office HP MFP M130fn
# HP ETHERNET MULTI-ENVIRONMENT
if (sysdesc !~ "^HP ETHERNET MULTI-ENVIRONMENT")
  exit(0);

model = "unknown";
fw_version = "unknown";

set_kb_item(name: "hp/printer/detected", value: TRUE);
set_kb_item(name: "hp/printer/snmp/detected", value: TRUE);
set_kb_item(name: "hp/printer/snmp/port", value: port);
set_kb_item(name: "hp/printer/snmp/" + port + "/banner", value:sysdesc);

mod_oid = "1.3.6.1.2.1.25.3.2.1.3.1";
mod = snmp_get(port: port, oid: mod_oid);
if (mod && mod != "") {
  model = mod;
  set_kb_item(name: "hp/printer/snmp/" + port + "/concludedMod", value: mod);
  set_kb_item(name: "hp/printer/snmp/" + port + "/concludedModOID", value: mod_oid);

  model = ereg_replace(string: model, pattern: "( Wide Format)?( All-in-One)?( Printer)?( Series)?",
                       replace: "", icase: TRUE);
}

# nb: fw-rom-datecode: Identifies the base system firmware date code.
# We will get a string with a hex code of the firmware date code. E.g. 01 15 32 30 32 30 31 30 32 32
# The first 2 hex numbers seem to be not relevant so the end hex code is just 32 30 32 30 31 30 32 32
# (20201022)
fw_oid = "1.3.6.1.4.1.11.2.3.9.4.2.1.1.3.5.0";
vers = snmp_get(port: port, oid: fw_oid);
if (vers) {
  vers = split(vers, sep: " ", keep: FALSE);
  if (max_index(vers) > 1) {
    fw_version = "";
    for (i = 2; i < max_index(vers); i++)
      fw_version += hex2str(vers[i]);
  } else {
    # 2022-01-21
    fw_version = str_replace(string: vers[0], find: "-", replace: "");
  }

  set_kb_item(name: "hp/printer/snmp/" + port + "/concludedFwOID", value: fw_oid);
}

set_kb_item(name: "hp/printer/snmp/" + port + "/model", value: model);
set_kb_item(name: "hp/printer/snmp/" + port + "/fw_version", value: fw_version);

exit(0);
