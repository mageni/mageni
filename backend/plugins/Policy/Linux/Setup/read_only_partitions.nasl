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
  script_oid("1.3.6.1.4.1.25623.1.0.150100");
  script_version("2020-07-29T07:27:10+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 14:33:52 +0100 (Thu, 23 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: List partitions mounted in read only mode");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("linux_list_mounted_filesystems.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://linux.die.net/man/8/mount");

  script_tag(name:"summary", value:"Mounting partitions in read-only mode prevent files from being
modified.

Note that, depending on the filesystem type, state and kernel behavior, the system may still write
to the device. For example, Ext3 or ext4 will replay its journal if the filesystem is dirty. To
prevent this kind of write access, you may want to mount ext3 or ext4 filesystem with 'ro, noload'
mount options or set the block device to read-only mode.

Note: This script lists all partitions mounted in 'ro' mode.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");
include("misc_func.inc");

cmd = "mount | grep -w ro";
title = "List partitions mounted in read only mode";
solution = "mount -o remount,ro PARTITION";
test_type = "Manual Check";
default = "None";
compliant = "yes";

if(get_kb_item("linux/mount/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not get information about partitions";
}else{
  partitions = get_kb_list("linux/mount/device");
  foreach partition (partitions){
    options = get_kb_item("linux/mount/" + partition + "/options");
    options_list = split(options, sep:",", keep:FALSE);
    if(in_array(search:"ro", array:options_list)){
      value += "," + partition;
    }
  }

  if(value)
    value = str_replace(string:value, find:",", replace:"", count:1);
  else
    value = "None";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);