# Copyright (C) 2019 Greenbone Networks GmbH
#
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.109733");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2019-01-15 08:27:43 +0100 (Tue, 15 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: GRUB bootloader password");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_boot_grub_config_files.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Password protection", type:"radio", value:"Enabled;Disabled", id:1);

  script_xref(name:"URL", value:"https://www.techrepublic.com/article/how-to-password-protect-your-grub-menu/");

  script_tag(name:"summary", value:"GRUB is the bootloader mainly used on Linux systems. If
protected with a password, users can not enter or change boot parameters without a password.");

  exit(0);
}

include("policy_functions.inc");

cmd = "grep 'password' /boot/*/menu.lst /boot/*/user.cfg /boot/*/grub.cfg";
title = "Password protected GRUB bootloader";
solution = "Run 'grub-md5-crypt' or 'grub-mkpasswd-pbkdf2', copy password hash to grub config file, run 'update-grub'";
test_type = "SSH_Cmd";
default = script_get_preference("Password protection", id:1);

if(get_kb_item("Policy/linux/sysctl/conf/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux//etc/sysconfig/init/content/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not read /etc/sysconfig/init";
}else{
  grub_config_files = get_kb_list("Policy/linux/grub/files/*");
  foreach file (grub_config_files){
    if(get_kb_item("Policy/linux/" + file + "/content/ERROR"))
      continue;

    read_file = TRUE;
    content = get_kb_item("Policy/linux/" + file + "/content");
    grep = egrep(string:content, pattern:"password", icase:TRUE);
    foreach line (split(grep)){
      if(line =~ "^\s*password --md5" || line =~ "^\s*password_pbkdf2" || line =~ "^\s*GRUB2_PASSWORD=")
        value = "Enabled";
    }

  }

  if(!read_file){
    value = "Error";
    compliant = "incomplete";
    comment = "Could not read any GRUB config file";
  }else if(!value){
    value = "Disabled";
  }

  compliant = policy_setting_exact_match(value:value, set_point:default);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);