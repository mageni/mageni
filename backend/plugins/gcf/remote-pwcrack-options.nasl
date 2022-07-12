###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-pwcrack-options.nasl 11543 2018-09-21 20:25:26Z cfischer $
#
# Remote password cracking - common options
#
# Based on hydra scripts by Michel Arboi <arboi@alussinan.org>
#
# Authors:
# Vlatko Kosturjak <kost@linux.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80104");
  script_version("$Revision: 11543 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-21 22:25:26 +0200 (Fri, 21 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-08-10 08:41:48 +0200 (Mon, 10 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Password cracking (NASL wrappers common options)");
  script_category(ACT_SETTINGS);
  script_copyright("This script is Copyright (C) 2009 Vlatko Kosturjak");
  script_family("Brute force attacks");
  script_dependencies("toolcheck.nasl");
  script_mandatory_keys("Tools/Present/pd_or_ncrack");

  script_add_preference(name:"Logins file : ", value:"", type:"file");
  script_add_preference(name:"Passwords file : ", value:"", type:"file");
  script_add_preference(name:"Number of parallel tasks :", value:"16", type:"entry");
  script_add_preference(name:"Timeout (in seconds) :", value:"30", type:"entry");
  script_add_preference(name:"Try empty passwords", type:"checkbox", value:"no");
  script_add_preference(name:"Try login as password", type:"checkbox", value:"no");
  script_add_preference(name:"Exit as soon as an account is found", type:"checkbox", value:"no");
  script_add_preference(name:"Add accounts found by other plugins to login file", type:"checkbox", value:"yes");

  script_tag(name:"summary", value:"This plugin sets options for the various password cracking tools.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

# Exit if nasl version is too old (<2200)
if (! defined_func("script_get_preference_file_location"))
{
  log_message(port: 0, data: "NVT not executed because of an too old openvas-libraries version.");
  exit(0);
}

#

function mk_login_file(logins)
{
  local_var	tmp1,tmp2, dir, list, i, u;
  dir = get_tmp_dir();
  if (! dir) return logins;	# Abnormal condition
  for (i = 1; TRUE; i ++)
  {
    u = get_kb_item("SMB/Users/"+i);
    if (! u) break;
    list = strcat(list, u, '\n');
  }
# Add here results from other plugins
  if (! list) return logins;
  tmp1 = strcat(dir, 'pwcrack-'+ get_host_ip() + '-' + rand());
  tmp2 = strcat(dir, 'pwcrack-'+ get_host_ip() + '-' + rand());
  if (fwrite(data: list, file: tmp1) <= 0)	# File creation failed
    return logins;
  if (! logins) return tmp1;
  pread(cmd: "sort", argv: make_list("sort", "-u", tmp1, logins, "-o", tmp2));
  unlink(tmp1);
  return tmp2;
}


p = script_get_preference_file_location("Passwords file : ");
if (!p ) exit(0);
set_kb_item(name: "Secret/pwcrack/passwords_file", value: p);

# No login file is necessary for SNMP, VNC and Cisco; and a login file
# may be made from other plugins results. So we do not exit if this
# option is void.
a = script_get_preference("Add accounts found by other plugins to login file");
p = script_get_preference_file_location("Logins file : ");
if ("no" >!< a) p = mk_login_file(logins: p);
set_kb_item(name: "Secret/pwcrack/logins_file", value: p);

p = script_get_preference("Timeout (in seconds) :");
t = int(p);
if (t <= 0) t = 30;
set_kb_item(name: "/tmp/pwcrack/timeout", value: t);

p = script_get_preference("Number of parallel tasks :");
t = int(p);
if (t <= 0) t = 16;
set_kb_item(name: "/tmp/pwcrack/tasks", value: t);

p = script_get_preference("Try empty passwords");
set_kb_item(name: "/tmp/pwcrack/empty_password", value: "yes" >< p);

p = script_get_preference("Try login as password");
set_kb_item(name: "/tmp/pwcrack/login_password", value: "yes" >< p);

p = script_get_preference("Exit as soon as an account is found");
set_kb_item(name: "/tmp/pwcrack/exit_ASAP", value: "yes" >< p);

