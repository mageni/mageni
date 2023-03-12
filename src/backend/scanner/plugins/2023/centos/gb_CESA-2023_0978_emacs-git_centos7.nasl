# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.884275");
  script_version("2023-03-03T10:59:40+0000");
  script_cve_id("CVE-2022-23521", "CVE-2022-41903");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-03 10:59:40 +0000 (Fri, 03 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-02 02:00:36 +0000 (Thu, 02 Mar 2023)");
  script_name("CentOS: Security Advisory for emacs-git (CESA-2023:0978)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2023:0978");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2023-March/086377.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'emacs-git'
  package(s) announced via the CESA-2023:0978 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Git is a distributed revision control system with a decentralized
architecture. As opposed to centralized version control systems with a
client-server model, Git ensures that each working copy of a Git repository
is an exact copy with complete revision history. This not only allows the
user to work on and contribute to projects without the need to have
permission to push the changes to their official repositories, but also
makes it possible for the user to work with no network connection.

Security Fix(es):

  * git: gitattributes parsing integer overflow (CVE-2022-23521)

  * git: Heap overflow in `git archive`, `git log --format` leading to RCE
(CVE-2022-41903)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'emacs-git' package(s) on CentOS 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"emacs-git", rpm:"emacs-git~1.8.3.1~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-git-el", rpm:"emacs-git-el~1.8.3.1~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git", rpm:"git~1.8.3.1~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-all", rpm:"git-all~1.8.3.1~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-bzr", rpm:"git-bzr~1.8.3.1~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-cvs", rpm:"git-cvs~1.8.3.1~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-daemon", rpm:"git-daemon~1.8.3.1~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-email", rpm:"git-email~1.8.3.1~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-gnome-keyring", rpm:"git-gnome-keyring~1.8.3.1~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-gui", rpm:"git-gui~1.8.3.1~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-hg", rpm:"git-hg~1.8.3.1~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-instaweb", rpm:"git-instaweb~1.8.3.1~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitk", rpm:"gitk~1.8.3.1~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-p4", rpm:"git-p4~1.8.3.1~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-svn", rpm:"git-svn~1.8.3.1~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitweb", rpm:"gitweb~1.8.3.1~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Git", rpm:"perl-Git~1.8.3.1~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Git-SVN", rpm:"perl-Git-SVN~1.8.3.1~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);