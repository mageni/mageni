###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for sudo RHSA-2013:1701-02
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871085");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-11-21 10:44:31 +0530 (Thu, 21 Nov 2013)");
  script_cve_id("CVE-2013-1775", "CVE-2013-2776", "CVE-2013-2777");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for sudo RHSA-2013:1701-02");


  script_tag(name:"affected", value:"sudo on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"insight", value:"The sudo (superuser do) utility allows system administrators to give
certain users the ability to run commands as root.

A flaw was found in the way sudo handled time stamp files. An attacker able
to run code as a local user and with the ability to control the system
clock could possibly gain additional privileges by running commands that
the victim user was allowed to run via sudo, without knowing the victim's
password. (CVE-2013-1775)

It was found that sudo did not properly validate the controlling terminal
device when the tty_tickets option was enabled in the /etc/sudoers file.
An attacker able to run code as a local user could possibly gain additional
privileges by running commands that the victim user was allowed to run via
sudo, without knowing the victim's password. (CVE-2013-2776, CVE-2013-2777)

This update also fixes the following bugs:

  * Previously, sudo did not support netgroup filtering for sources from the
System Security Services Daemon (SSSD). Consequently, SSSD rules were
applied to all users even when they did not belong to the specified
netgroup. With this update, netgroup filtering for SSSD sources has been
implemented. As a result, rules with a netgroup specification are applied
only to users that are part of the netgroup. (BZ#880150)

  * When the sudo utility set up the environment in which it ran a command,
it reset the value of the RLIMIT_NPROC resource limit to the parent's value
of this limit if both the soft (current) and hard (maximum) values of
RLIMIT_NPROC were not limited. An upstream patch has been provided to
address this bug and RLIMIT_NPROC can now be set to 'unlimited'.
(BZ#947276)

  * Due to the refactoring of the sudo code by upstream, the SUDO_USER
variable that stores the name of the user running the sudo command was not
logged to the /var/log/secure file as before. Consequently, user name
'root' was always recorded instead of the real user name. With this update,
the previous behavior of sudo has been restored. As a result, the expected
user name is now written to /var/log/secure. (BZ#973228)

  * Due to an error in a loop condition in sudo's rule listing code, a buffer
overflow could have occurred in certain cases. This condition has been
fixed and the buffer overflow no longer occurs. (BZ#994626)

In addition, this update adds the following enhancements:

  * With this update, sudo has been modified to send debug messages about
netgroup matching to the debug log. These messages should provide better
understanding of how sudo matches netgroup d ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-November/msg00034.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.8.6p3~12.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sudo-debuginfo", rpm:"sudo-debuginfo~1.8.6p3~12.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
