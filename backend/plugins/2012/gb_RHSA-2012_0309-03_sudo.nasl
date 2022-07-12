###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for sudo RHSA-2012:0309-03
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-February/msg00047.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870553");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-02-21 18:56:44 +0530 (Tue, 21 Feb 2012)");
  script_cve_id("CVE-2011-0010");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for sudo RHSA-2012:0309-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"sudo on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The sudo (superuser do) utility allows system administrators to give
  certain users the ability to run commands as root.

  A flaw was found in the sudo password checking logic. In configurations
  where the sudoers settings allowed a user to run a command using sudo
  with only the group ID changed, sudo failed to prompt for the user's
  password before running the specified command with the elevated group
  privileges. (CVE-2011-0010)

  In addition, this update fixes the following bugs:

  * A NULL pointer dereference bug caused the sudo utility to terminate
  unexpectedly with a segmentation fault. This happened if the utility was
  run with the -g option and configured not to demand the password from the
  user who ran the sudo utility. With this update, the code has been modified
  and the problem no longer occurs. (BZ#673072)

  * The sudo utility failed to load sudoers from an LDAP (Lightweight
  Directory Access Protocol) server after the sudo tool was upgraded. This
  happened because the upgraded nsswitch.conf file did not contain the
  instruction to search for sudoers on the LDAP server. This update adds the
  lost instruction to /etc/nsswitch.conf and the system searches for sources
  of sudoers on the local file system and then on LDAP, if applicable.
  (BZ#617061)

  * The sudo tool interpreted a Runas alias specifying a group incorrectly as
  a user alias and the alias seemed to be ignored. With this update, the code
  for interpreting such aliases has been modified and the Runas group aliases
  are honored as expected. (BZ#627543)

  * Prior to this update, sudo did not parse comment characters (#) in the
  ldap.conf file correctly and could fail to work. With this update, parsing
  of the LDAP configuration file has been modified and the comment characters
  are parsed correctly. (BZ#750318)

  * The sudo utility formats its output to fit the width of the terminal
  window. However, this behavior is undesirable if the output is redirected
  through a pipeline. With this update, the output formatting is not applied
  in the scenario described. (BZ#697111)

  * Previously, the sudo utility performed Security-Enhanced Linux (SELinux)
  related initialization after switching to an unprivileged user. This
  prevented the correct setup of the SELinux environment before executing the
  specified command and could potentially cause an access denial. The bug has
  been fixed by backporting the SELinux related code and the execution model
  from a newer version of sudo. (BZ#477185)

  * On execv(3) function failure, the sudo tool executed a ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.7.2p1~13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sudo-debuginfo", rpm:"sudo-debuginfo~1.7.2p1~13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
