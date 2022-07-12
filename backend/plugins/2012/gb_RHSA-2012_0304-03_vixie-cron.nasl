###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for vixie-cron RHSA-2012:0304-03
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-February/msg00056.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870550");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-21 18:56:37 +0530 (Tue, 21 Feb 2012)");
  script_cve_id("CVE-2010-0424");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_name("RedHat Update for vixie-cron RHSA-2012:0304-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vixie-cron'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"vixie-cron on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The vixie-cron package contains the Vixie version of cron. Cron is a
  standard UNIX daemon that runs specified programs at scheduled times. The
  vixie-cron package adds improved security and more powerful configuration
  options to the standard version of cron.

  A race condition was found in the way the crontab program performed file
  time stamp updates on a temporary file created when editing a user crontab
  file. A local attacker could use this flaw to change the modification time
  of arbitrary system files via a symbolic link attack. (CVE-2010-0424)

  Red Hat would like to thank Dan Rosenberg for reporting this issue.

  This update also fixes the following bugs:

  * Cron jobs of users with home directories mounted on a Lightweight
  Directory Access Protocol (LDAP) server or Network File System (NFS) were
  often refused because jobs were marked as orphaned (typically due to a
  temporary NSS lookup failure, when NIS and LDAP servers were unreachable).
  With this update, a database of orphans is created, and cron jobs are
  performed as expected. (BZ#455664)

  * Previously, cron did not log any errors if a cron job file located in the
  /etc/cron.d/ directory contained invalid entries. An upstream patch has
  been applied to address this problem and invalid entries in the cron job
  files now produce warning messages. (BZ#460070)

  * Previously, the '@reboot' crontab macro incorrectly ran jobs when the
  crond daemon was restarted. If the user used the macro on multiple
  machines, all entries with the '@reboot' option were executed every time
  the crond daemon was restarted. With this update, jobs are executed only
  when the machine is rebooted. (BZ#476972)

  * The crontab utility is now compiled as a position-independent executable
  (PIE), which enhances the security of the system. (BZ#480930)

  * When the parent crond daemon was stopped, but a child crond daemon was
  running (executing a program), the 'service crond status' command
  incorrectly reported that crond was running. The source code has been
  modified, and the 'service crond status' command now correctly reports that
  crond is stopped. (BZ#529632)

  * According to the pam(8) manual page, the cron daemon, crond, supports
  access control with PAM (Pluggable Authentication Module). However, the PAM
  configuration file for crond did not export environment variables correctly
  and, consequently, setting PAM variables via cron did not work. This update
  includes a corrected /etc/pam.d/crond file that exports environmen ...

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

  if ((res = isrpmvuln(pkg:"vixie-cron", rpm:"vixie-cron~4.1~81.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vixie-cron-debuginfo", rpm:"vixie-cron-debuginfo~4.1~81.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
