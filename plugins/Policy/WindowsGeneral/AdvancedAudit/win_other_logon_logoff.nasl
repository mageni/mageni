# Copyright (C) 2018 Greenbone Networks GmbH
#
# Text descriptions excerpted from a referenced source are
# Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.109588");
  script_version("2019-12-13T11:11:18+0000");
  script_tag(name:"last_modification", value:"2019-12-13 11:11:18 +0000 (Fri, 13 Dec 2019)");
  script_tag(name:"creation_date", value:"2018-08-20 10:10:59 +0200 (Mon, 20 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Audit Other Logon/Logoff Events");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl", "win_AdvancedPolicySettings.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"Success and Failure;Success;Failure;No Auditing");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-logonlogoff-events");

  script_tag(name:"summary", value:"Audit Other Logon/Logoff Events determines whether Windows
generates audit events for other logon or logoff events.

These other logon or logoff events include:

  - A Remote Desktop session connects or disconnects.

  - A workstation is locked or unlocked.

  - A screen saver is invoked or dismissed.

  - A replay attack is detected. This event indicates that a Kerberos request was received twice with
identical information. This condition could also be caused by network misconfiguration.

  - A user is granted access to a wireless network. It can be either a user account or the computer
account.

  - A user is granted access to a wired 802.1x network. It can be either a user account or the
computer account.

Logon events are essential to understanding user activity and detecting potential attacks.

(C) Microsoft Corporation 2017.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Audit Other Logon/Logoff Events";
solution = "Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audit
Policies/Logon / Logoff/" + title;
key = "WMI/AdvancedPolicy/OtherLogonLogoffEvents";
test = "auditpol /get /category:*";
test_type = "WMI_Query";
default = script_get_preference("Value");

if(!policy_verify_win_ver(min_ver:win_min_ver)){
  results = policy_report_wrong_os(target_os:target_os);
}else{
  results = policy_win_get_advanced_audit_results(key:key, default:default);
}

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:test, info:comment);
policy_set_kbs(type:test_type, cmd:test, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
