# Copyright (C) 2020 Greenbone Networks GmbH
#
# Text descriptions are largely excerpted from the referenced
# website, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.150156");
  script_version("2020-03-11T14:40:46+0000");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-03-11 14:37:36 +0000 (Wed, 11 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Read /etc/selinux/config  (KB)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://linux.die.net/man/8/selinux");

  script_tag(name:"summary", value:"The /etc/selinux/config configuration file controls whether
SELinux is enabled or disabled, and if enabled, whether SELinux operates in permissive mode or
enforcing mode. The SELINUX variable may be set to any one of disabled, permissive, or enforcing to
select one of these options. The disabled option completely disables the SELinux kernel and
application code, leaving the system running without any SELinux protection. The permissive option
enables the SELinux code, but causes it to operate in a mode where accesses that would be denied by
policy are permitted but audited. The enforcing option enables the SELinux code and causes it to
enforce access denials as well as auditing them. Permissive mode may yield a different set of
denials than enforcing mode, both because enforcing mode will prevent an operation from proceeding
past the first denial and because some application code will fall back to a less privileged mode of
operation if denied access.

Note: This script only stores information for other Policy Controls.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

file = "/etc/selinux/config";

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  set_kb_item(name:"Policy/linux/" + file + "/ERROR", value:TRUE);
  set_kb_item(name:"Policy/linux/" + file + "/stat/ERROR", value:TRUE);
  exit(0);
}

policy_linux_stat_file(socket:sock, file:file);
policy_linux_file_content(socket:sock, file:file);

exit(0);