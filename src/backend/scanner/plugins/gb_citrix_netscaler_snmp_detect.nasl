# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140666");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-01-12 09:26:50 +0700 (Fri, 12 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Citrix Netscaler Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdescr_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of Citrix Netscaler.");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port = snmp_get_port(default: 161);
sysdesc = snmp_get_sysdescr(port: port);

if (!sysdesc || sysdesc !~ "^NetScaler NS")
  exit(0);

set_kb_item(name: "citrix/netscaler/detected", value: TRUE);
set_kb_item(name: "citrix/netscaler/snmp/detected", value: TRUE);
set_kb_item(name: "citrix/netscaler/snmp/port", value: port);
set_kb_item(name: "citrix/netscaler/snmp/" + port + "/concluded", value: sysdesc);

version = "unknown";

# NetScaler NS12.0: Build 53.22.nc, Date: Dec 10 2017, 04:46:16
# NetScaler NS10.5: Build 60.7066.e.nc, Date: Nov 18 2016, 14:29:31
vers = eregmatch(pattern: "^NetScaler NS([0-9\.]+): (Build (([0-9\.]+))(.e)?.nc)?", string: sysdesc);
if (!isnull(vers[1])) {
  if (!isnull(vers[3]))
    version = vers[1] + "." + vers[3];
  else
    version = vers[1];

  # Enhanced Build
  if (!isnull(vers[5]))
    set_kb_item(name: "citrix/netscaler/enhanced_build", value: TRUE);
}

set_kb_item(name: "citrix/netscaler/snmp/" + port + "/version", value: version);

exit(0);
