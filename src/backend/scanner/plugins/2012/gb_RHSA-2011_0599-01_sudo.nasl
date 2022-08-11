###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for sudo RHSA-2011:0599-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-May/msg00021.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870711");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-06-06 10:51:51 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2011-0010");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for sudo RHSA-2011:0599-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"sudo on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The sudo (superuser do) utility allows system administrators to give
  certain users the ability to run commands as root.

  A flaw was found in the sudo password checking logic. In configurations
  where the sudoers settings allowed a user to run a command using sudo with
  only the group ID changed, sudo failed to prompt for the user's password
  before running the specified command with the elevated group privileges.
  (CVE-2011-0010)

  This update also fixes the following bugs:

  * When the '/etc/sudoers' file contained entries with multiple hosts,
  running the 'sudo -l' command incorrectly reported that a certain user does
  not have permissions to use sudo on the system. With this update, running
  the 'sudo -l' command now produces the correct output. (BZ#603823)

  * Prior to this update, the manual page for sudoers.ldap was not installed,
  even though it contains important information on how to set up an LDAP
  (Lightweight Directory Access Protocol) sudoers source, and other documents
  refer to it. With this update, the manual page is now properly included in
  the package. Additionally, various POD files have been removed from the
  package, as they are required for build purposes only. (BZ#634159)

  * The previous version of sudo did not use the same location for the LDAP
  configuration files as the nss_ldap package. This has been fixed and sudo
  now looks for these files in the same location as the nss_ldap package.
  (BZ#652726)

  * When a file was edited using the 'sudo -e file' or the 'sudoedit file'
  command, the editor being executed for this task was logged only as
  'sudoedit'. With this update, the full path to the executable being used as
  an editor is now logged (instead of 'sudoedit'). (BZ#665131)

  * A comment regarding the 'visiblepw' option of the 'Defaults' directive
  has been added to the default '/etc/sudoers' file to clarify its usage.
  (BZ#688640)

  * This erratum upgrades sudo to upstream version 1.7.4p5, which provides a
  number of bug fixes and enhancements over the previous version. (BZ#615087)

  All users of sudo are advised to upgrade to this updated package, which
  resolves these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.7.4p5~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sudo-debuginfo", rpm:"sudo-debuginfo~1.7.4p5~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
