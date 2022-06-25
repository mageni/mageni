# Copyright (C) 2015 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105197");
  script_version("2022-03-14T10:17:50+0000");
  script_tag(name:"last_modification", value:"2022-03-17 11:18:10 +0000 (Thu, 17 Mar 2022)");
  script_tag(name:"creation_date", value:"2015-02-10 15:03:19 +0100 (Tue, 10 Feb 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Fortinet FortiGate Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("fortinet/fortios/system_status");

  script_tag(name:"summary", value:"SSH login-based detection of Fortinet FortiGate.");

  exit(0);
}

include("host_details.inc");

system = get_kb_item("fortinet/fortios/system_status");
if ("FortiGate" >!< system)
  exit(0);

port = get_kb_item("fortinet/fortios/ssh-login/port");

set_kb_item(name: "fortinet/fortigate/detected", value: TRUE);
set_kb_item(name: "fortinet/fortigate/ssh-login/detected", value: TRUE);
set_kb_item(name: "fortinet/fortigate/ssh-login/port", value: port);

model = "unknown";
version = "unknown";
build = "unknown";
patch = "unknown";

# FortiGate-VM64 # get system status
# Version: FortiGate-VM64 v5.6.2,build1486,170816 (GA)
# Virus-DB: 1.00123(2015-12-11 13:18)
# Extended DB: 1.00000(2012-10-17 15:46)
# IPS-DB: 6.00741(2015-12-01 02:30)
# IPS-ETDB: 0.00000(2001-01-01 00:00)
# APP-DB: 6.00741(2015-12-01 02:30)
# INDUSTRIAL-DB: 6.00741(2015-12-01 02:30)
# Serial-Number: FGVMEVBZZSBYO35
# IPS Malicious URL Database: 1.00001(2015-01-01 01:01)
# Botnet DB: 1.00000(2012-05-28 22:51)
# License Status: Valid
# Evaluation License Expires: Sat Mar 26 02:42:45 2022
# VM Resources: 1 CPU/1 allowed, 996 MB RAM/1024 MB allowed
# BIOS version: 04000002
# Log hard disk: Available
# Hostname: FortiGate-VM64
# Operation Mode: NAT
# Current virtual domain: root
# Max number of virtual domains: 1
# Virtual domains status: 1 in NAT mode, 0 in TP mode
# Virtual domain configuration: disable
# FIPS-CC mode: disable
# Current HA mode: standalone
# Branch point: 1486
# Release Version Information: GA
# FortiOS x86-64: Yes
# System time: Sun Mar 13 23:57:36 2022

mod = eregmatch(string: system, pattern: "Version\s*:\s*(FortiGate-[^ ]+)");
if (!isnull(mod[1]))
  model = mod[1];

vers = eregmatch(string: system, pattern: 'Version\\s*:\\s*FortiGate[^ ]* v([0-9.]+)[^\r\n]*');
if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "fortinet/fortigate/ssh-login/" + port + "/concluded", value: vers[0]);
}

bld = eregmatch(string: vers[0], pattern: ",build([^,]+)");
if (!isnull(bld[1]))
  build = ereg_replace(string: bld[1], pattern: "^0*", replace: "");

p = eregmatch(string: system, pattern: "Patch\s+([0-9]+)");
if (!isnull(p[1]))
  patch = p[1];

set_kb_item(name: "fortinet/fortigate/ssh-login/" + port + "/model", value: model);
set_kb_item(name: "fortinet/fortigate/ssh-login/" + port + "/version", value: version);
set_kb_item(name: "fortinet/fortigate/ssh-login/" + port + "/build", value: build);
set_kb_item(name: "fortinet/fortigate/ssh-login/" + port + "/patch", value: patch);

exit(0);
