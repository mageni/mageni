# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106109");
  script_version("2023-03-02T10:09:16+0000");
  script_tag(name:"last_modification", value:"2023-03-02 10:09:16 +0000 (Thu, 02 Mar 2023)");
  script_tag(name:"creation_date", value:"2016-06-24 14:37:30 +0700 (Fri, 24 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Meinberg LANTIME Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Meinberg LANTIME NTP Timeserver
  devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdescr_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

if(!sysdesc = snmp_get_sysdescr(port: port))
  exit(0);

# Meinberg LANTIME SF1010-SC8-35 V7.00.007-sf1000
# Meinberg LANTIME M300 V6.24.024
if ("Meinberg LANTIME" >< sysdesc) {

  model = "unknown";
  version = "unknown";

  # nb:
  # - From the SF1010-SC8-35 example above we only want to include SF1010 here...
  # - SF seems to be "SyncFire" devices
  # - "/" is included here because there seems to be also devices like M300/PZF (no SNMP banner was
  #   found so far for these)
  mod = eregmatch(pattern: "LANTIME ([A-Z0-9/]+)", string: sysdesc, icase: FALSE);
  if (!isnull(mod[1]))
    model = mod[1];

  vers = eregmatch(pattern: " V([0-9.]+)", string: sysdesc);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "meinberg/lantime/detected", value: TRUE);
  set_kb_item(name: "meinberg/lantime/snmp/detected", value: TRUE);
  set_kb_item(name: "meinberg/lantime/snmp/port", value: port);
  set_kb_item(name: "meinberg/lantime/snmp/" + port + "/model", value: model);
  set_kb_item(name: "meinberg/lantime/snmp/" + port + "/fw_version", value: version);
  set_kb_item(name: "meinberg/lantime/snmp/" + port + "/concluded", value: sysdesc);
}

exit(0);
