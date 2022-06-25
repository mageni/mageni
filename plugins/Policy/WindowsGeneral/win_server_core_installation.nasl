# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.150009");
  script_version("2019-12-16T11:36:02+0000");
  script_tag(name:"last_modification", value:"2019-12-16 11:36:02 +0000 (Mon, 16 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-13 11:08:46 +0100 (Fri, 13 Dec 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Server Core Installation");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"Server Core");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/windows-server/administration/server-core/what-is-server-core");

  script_tag(name:"summary", value:"The Server Core option is a minimal installation option that is
available when you are deploying the Standard or Datacenter edition of Windows Server. Server Core
includes most but not all server roles. Server Core has a smaller disk footprint, and therefore a
smaller attack surface due to a smaller code base.

(C) Microsoft Corporation 2018.

Check for 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion!InstallationType'.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = "Microsoft Windows Server 2012 or later";
win_min_ver = "6.1";
title = "Determining Whether Server Core Is Running";
solution = "Install Microsoft Windows Server as Server Core.";
type = "HKLM";
key = "Software\Microsoft\Windows NT\CurrentVersion";
item = "InstallationType";
reg_path = type + "\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference("Value");

if(!policy_verify_win_ver(min_ver:win_min_ver))
  results = policy_report_wrong_os(target_os:target_os);
else
  results = policy_match_reg_sz(key:key, item:item, type:type, default:default, partial:FALSE,
    multi_sz:FALSE);

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
