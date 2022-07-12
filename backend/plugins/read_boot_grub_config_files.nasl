# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.150178");
  script_version("2020-06-22T08:41:58+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-03-23 13:25:47 +0000 (Mon, 23 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Read GRUB config files (KB)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://www.tutorialspoint.com/what-is-grub-in-linux");

  script_tag(name:"summary", value:"The GRUB (Grand Unified Bootloader) is a bootloader available
from the GNU project. A bootloader is very important as it is impossible to start an operating
system without it. It is the first program which starts when the program is switched on. The
bootloader transfers the control to the operating system kernel.

This script searches for grub.cfg, menu.lst and user.cfg in /boot/ directory.

Note: This script only stores information for other Policy Controls.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  set_kb_item(name:"Policy/linux/grub/ssh/ERROR", value:TRUE);
  exit(0);
}

bootloader_files = make_list();

grub_cfg_files = ssh_find_file(file_name:"/boot/grub.cfg", sock:sock);
menu_lst_files = ssh_find_file(file_name:"/boot/menu.lst", sock:sock);
user_cfg_files = ssh_find_file(file_name:"/boot/user.cfg", sock:sock);

if(grub_cfg_files)
  bootloader_files = make_list(bootloader_files, grub_cfg_files);

if(menu_lst_files)
  bootloader_files = make_list(bootloader_files, menu_lst_files);

if(user_cfg_files)
  bootloader_files = make_list(bootloader_files, user_cfg_files);


foreach file (bootloader_files){
  file = chomp(file);
  set_kb_item(name:"Policy/linux/grub/files/", value:file);
  policy_linux_stat_file(socket:sock, file:file);
  policy_linux_file_content(socket:sock, file:file);
}

exit(0);
