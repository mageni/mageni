# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.143679");
  script_version("2020-04-09T08:45:31+0000");
  script_tag(name:"last_modification", value:"2020-04-09 11:12:54 +0000 (Thu, 09 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-08 02:12:28 +0000 (Wed, 08 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Huawei VRP Detection (SSH)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("huawei/vrp/display_version");

  script_tag(name:"summary", value:"This script performs an SSH based detection of Huawei Versatile Routing Platform (VRP) network devices.");

  exit(0);
}

if (!display_version = get_kb_item("huawei/vrp/display_version"))
  exit(0);

port = get_kb_item("huawei/vrp/ssh/port");

set_kb_item(name: "huawei/vrp/detected", value: TRUE);
set_kb_item(name: "huawei/vrp/ssh-login/port", value: port);

model = "unknown";
version = "unknown";
patch_version = "unknown";

# HUAWEI S5735-S24T4X Routing Switch uptime
# HUAWEI NE05E-SQ uptime
# Huawei AP5030DN Router uptime
# HUAWEI S7703 Terabit Routing Switch uptime
#
# nb: Some devices seems to not support "display device" so we're first trying this one...
mod = eregmatch(pattern: "HUAWEI ([^ ]+) ((Terabit )?Routing Switch |Router )?uptime", string: display_version, icase: TRUE);
if (!isnull(mod[1])) {
  concluded = '\n  - Model:           ' + mod[0];
  model = mod[1];
}

# ... and falling back to display device if the extraction above failed.
if (model == "unknown") {
  display_device = get_kb_item("huawei/vrp/display_device");
  if (display_device) {

    # S7712's Device status:
    # S5735-S24T4X's Device status:
    # NE05E-SQ's Device status:
    device = egrep(pattern: "(.+)'s Device status:", string: display_device, icase: FALSE);
    if (device) {
      mod = eregmatch(pattern: "(.+)'s Device status:", string: device, icase: FALSE);
      if (!isnull(mod[1])) {
        concluded = '\n  - Model:           ' + mod[0];
        model = mod[1];
      }
    }
  }
}

# VRP (R) software, Version 5.170 (S5735 V200R019C00SPC500)
# VRP (R) software, Version 8.190 (NE05E-SQ V300R005C10SPC100)
# VRP (R) software, Version 5.130 (AP5030DN FIT V200R010C00)
# VRP (R) software, Version 5.150 (S7700 V200R007C00SPC100)
vers = eregmatch(pattern: 'Version [0-9.]+[^\r\n]*(V[0-9A-Z]+)\\)', string: display_version);
if (!isnull(vers[1])) {
  version = vers[1];
  concluded += '\n  - Version:         ' + vers[0];
}

patch_info = get_kb_item("huawei/vrp/patch-information");

# Patch version    :    V200R010C00SPH
# Patch Package Version:V200R013SPH
patch = eregmatch(pattern: "Patch (version|Package Version)[^:]*:[^V]+(V[0-9A-Z]+)", string: patch_info);
if (!isnull(patch[2])) {
  patch_version = patch[2];
  concluded += '\n  - Installed patch: ' + patch[0];
} else if ("Info: No patch exists." >< patch_info) {
  patch_version = "No patch installed";
  concluded += '\n  - Installed patch: "Info: No patch exists."';
}

if (concluded)
  set_kb_item(name: "huawei/vrp/ssh-login/" + port + "/concluded", value: concluded);

set_kb_item(name: "huawei/vrp/ssh-login/" + port + "/model", value: model);
set_kb_item(name: "huawei/vrp/ssh-login/" + port + "/version", value: version);
set_kb_item(name: "huawei/vrp/ssh-login/" + port + "/patch", value: patch_version);

exit(0);
