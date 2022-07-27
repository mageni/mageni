###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for policycoreutils RHSA-2011:0414-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-April/msg00002.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870663");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-06-06 10:44:35 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2011-1011");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for policycoreutils RHSA-2011:0414-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'policycoreutils'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"policycoreutils on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The policycoreutils packages contain the core utilities that are
  required for the basic operation of a Security-Enhanced Linux (SELinux)
  system and its policies.

  It was discovered that the seunshare utility did not enforce proper file
  permissions on the directory used as an alternate temporary directory
  mounted as /tmp/. A local user could use this flaw to overwrite files or,
  possibly, execute arbitrary code with the privileges of a setuid or
  setgid application that relies on proper /tmp/ permissions, by running that
  application via seunshare. (CVE-2011-1011)

  Red Hat would like to thank Tavis Ormandy for reporting this issue.

  This update also introduces the following changes:

  * The seunshare utility was moved from the main policycoreutils subpackage
  to the policycoreutils-sandbox subpackage. This utility is only required
  by the sandbox feature and does not need to be installed by default.

  * Updated selinux-policy packages that add the SELinux policy changes
  required by the seunshare fixes.

  All policycoreutils users should upgrade to these updated packages, which
  correct this issue.");
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

  if ((res = isrpmvuln(pkg:"policycoreutils", rpm:"policycoreutils~2.0.83~19.8.el6_0", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"policycoreutils-debuginfo", rpm:"policycoreutils-debuginfo~2.0.83~19.8.el6_0", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"policycoreutils-gui", rpm:"policycoreutils-gui~2.0.83~19.8.el6_0", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"policycoreutils-newrole", rpm:"policycoreutils-newrole~2.0.83~19.8.el6_0", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"policycoreutils-python", rpm:"policycoreutils-python~2.0.83~19.8.el6_0", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"policycoreutils-sandbox", rpm:"policycoreutils-sandbox~2.0.83~19.8.el6_0", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"selinux-policy", rpm:"selinux-policy~3.7.19~54.el6_0.5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"selinux-policy-minimum", rpm:"selinux-policy-minimum~3.7.19~54.el6_0.5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"selinux-policy-mls", rpm:"selinux-policy-mls~3.7.19~54.el6_0.5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"selinux-policy-targeted", rpm:"selinux-policy-targeted~3.7.19~54.el6_0.5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
