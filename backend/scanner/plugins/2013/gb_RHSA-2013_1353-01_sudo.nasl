###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for sudo RHSA-2013:1353-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871048");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-10-03 10:17:42 +0530 (Thu, 03 Oct 2013)");
  script_cve_id("CVE-2013-1775", "CVE-2013-1776", "CVE-2013-2776");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for sudo RHSA-2013:1353-01");


  script_tag(name:"affected", value:"sudo on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"insight", value:"The sudo (superuser do) utility allows system administrators to give
certain users the ability to run commands as root.

A flaw was found in the way sudo handled time stamp files. An attacker able
to run code as a local user and with the ability to control the system
clock could possibly gain additional privileges by running commands that
the victim user was allowed to run via sudo, without knowing the victim's
password. (CVE-2013-1775)

It was found that sudo did not properly validate the controlling terminal
device when the tty_tickets option was enabled in the /etc/sudoers file. An
attacker able to run code as a local user could possibly gain additional
privileges by running commands that the victim user was allowed to run via
sudo, without knowing the victim's password. (CVE-2013-1776, CVE-2013-2776)

This update also fixes the following bugs:

  * Due to a bug in the cycle detection algorithm of the visudo utility,
visudo incorrectly evaluated certain alias definitions in the /etc/sudoers
file as cycles. Consequently, a warning message about undefined aliases
appeared. This bug has been fixed, /etc/sudoers is now parsed correctly by
visudo and the warning message no longer appears. (BZ#849679)

  * Previously, the 'sudo -l' command did not parse the /etc/sudoers file
correctly if it contained an Active Directory (AD) group. The file was
parsed only up to the first AD group information and then the parsing
failed with the following message:

    sudo: unable to cache group ADDOM\admingroup, already exists

With this update, the underlying code has been modified and 'sudo -l' now
parses /etc/sudoers containing AD groups correctly. (BZ#855836)

  * Previously, the sudo utility did not escape the backslash characters
contained in user names properly. Consequently, if a system used sudo
integrated with LDAP or Active Directory (AD) as the primary authentication
mechanism, users were not able to authenticate on that system. With this
update, sudo has been modified to process LDAP and AD names correctly and
the authentication process now works as expected. (BZ#869287)

  * Prior to this update, the 'visudo -s (strict)' command incorrectly parsed
certain alias definitions. Consequently, an error message was issued. The
bug has been fixed, and parsing errors no longer occur when using 'visudo

  - -s'. (BZ#905624)

All sudo users are advised to upgrade to this updated package, which
contains backported patches to correct these issues.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-September/msg00055.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.7.2p1~28.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sudo-debuginfo", rpm:"sudo-debuginfo~1.7.2p1~28.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
