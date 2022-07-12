# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109715");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2019-01-09 08:27:15 +0100 (Wed, 09 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Mounting of freevxfs filesystems");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_etc_modprobe_files.nasl", "read_lsmod_kernel_modules.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Status", type:"radio", value:"Disabled;Enabled", id:1);

  script_tag(name:"summary", value:"The freevxfs filesystem type is a free version of the Veritas
type filesystem.

Linux kernel modules which implement filesystems that are not needed by the local system should be
disabled.

Note: This script looks for entry 'install freevxfs /bin/true' in files in /etc/modprobe.d/*.conf and
if the module is loaded via lsmod command.");

  exit(0);
}

include("policy_functions.inc");

cmd = "lsmod; grep -r 'install freevxfs /bin/true' /etc/modprobe.d/*";
title = "Mounting of freevxfs filesystems";
solution = "Add or remove 'install freevxfs /bin/true' in config file (/etc/modprobe.d/*.conf) and run modprobe [-r] freevxfs";
test_type = "SSH_Cmd";
default = script_get_preference("Status", id:1);
default = "Disabled";
comment = "";

if(get_kb_item("Policy/linux//etc/modprobe.d/ERROR") || get_kb_item("Policy/linux/lsmod/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection";
}else if(get_kb_item("Policy/linux//etc/modprobe.d/NO_BASH")){
  value = "Error";
  compliant = "incomplete";
  comment = "Bash is not available on the target host but needed for this test.";
}else{
  if(get_kb_item("Policy/linux/module/freevxfs"))
    loaded = TRUE;

  foreach file (get_kb_list("Policy/linux//etc/modprobe.d")){
    if(get_kb_item("Policy/linux/" + file + "/content/ERROR"))
      continue;
    file_content = get_kb_item("Policy/linux/" + file + "/content");
    if(egrep(string:file_content, pattern:"^\s*install freevxfs /bin/true"))
      deactivated = TRUE;
  }

  if(loaded || !deactivated)
    value = "Enabled";
  else
    value = "Disabled";

  compliant = policy_setting_exact_match(value:value, set_point:default);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);