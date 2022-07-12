# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853136");
  script_version("2020-05-07T07:41:43+0000");
  script_cve_id("CVE-2017-15298", "CVE-2018-11233", "CVE-2018-11235", "CVE-2018-17456", "CVE-2019-1348", "CVE-2019-1349", "CVE-2019-1350", "CVE-2019-1351", "CVE-2019-1352", "CVE-2019-1353", "CVE-2019-1354", "CVE-2019-1387", "CVE-2019-19604", "CVE-2020-11008", "CVE-2020-5260");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-05-07 10:48:07 +0000 (Thu, 07 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-02 03:00:59 +0000 (Sat, 02 May 2020)");
  script_name("openSUSE: Security Advisory for git (openSUSE-SU-2020:0598-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00003.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git'
  package(s) announced via the openSUSE-SU-2020:0598-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for git fixes the following issues:

  Security issues fixed:

  * CVE-2020-11008: Specially crafted URLs may have tricked the credentials
  helper to providing credential information that is not appropriate for
  the protocol in use and host being contacted (bsc#1169936)

  git was updated to 2.26.1 (bsc#1169786, jsc#ECO-1628, bsc#1149792)

  - Fix git-daemon not starting after conversion from sysvinit to systemd
  service (bsc#1169605).

  * CVE-2020-5260: Specially crafted URLs with newline characters could have
  been used to make the Git client to send credential information for a
  wrong host to the attacker's site bsc#1168930

  git 2.26.0 (bsc#1167890, jsc#SLE-11608):

  * 'git rebase' now uses a different backend that is based on the 'merge'
  machinery by default. The 'rebase.backend' configuration variable
  reverts to old behaviour when set to  'apply'

  * Improved handling of sparse checkouts

  * Improvements to many commands and internal features

  git 2.25.2:

  * bug fixes to various subcommands in specific operations

  git 2.25.1:

  * 'git commit' now honors advise.statusHints

  * various updates, bug fixes and documentation updates

  git 2.25.0

  * The branch description ('git branch --edit-description') has been used
  to fill the body of the cover letters by the format-patch command, this
  has been enhanced so that the subject can also be filled.

  * A few commands learned to take the pathspec from the standard input
  or a named file, instead of taking it as the command line arguments,
  with the '--pathspec-from-file' option.

  * Test updates to prepare for SHA-2 transition continues.

  * Redo 'git name-rev' to avoid recursive calls.

  * When all files from some subdirectory were renamed to the root
  directory, the directory rename heuristics would fail to detect that as
  a rename/merge of the subdirectory to the root directory, which has been
  corrected.

  * HTTP transport had possible allocator/deallocator mismatch, which has
  been corrected.

  git 2.24.1:

  * CVE-2019-1348: The --export-marks option of fast-import is exposed also
  via the in-stream command feature export-marks=... and it allows
  overwriting arbitrary paths (bsc#1158785)

  * CVE-2019-1349: on Windows, when submodules are cloned recursively, under
  certain circumstances Git could be fooled into using the same Git
  directory twice (bsc#1158787)

  * CVE-2019-1350: Incorrect quoting of command-line arguments allowed
  remote code execution during a recursive clone in conjunction with SSH
  URLs (bsc#1158788)

  * CVE-2019-1351: on Windows mistakes drive letters outside of the
  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'git' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"git", rpm:"git~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-arch", rpm:"git-arch~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-core-debuginfo", rpm:"git-core-debuginfo~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-credential-gnome-keyring", rpm:"git-credential-gnome-keyring~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-credential-gnome-keyring-debuginfo", rpm:"git-credential-gnome-keyring-debuginfo~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-credential-libsecret", rpm:"git-credential-libsecret~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-credential-libsecret-debuginfo", rpm:"git-credential-libsecret-debuginfo~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-cvs", rpm:"git-cvs~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-daemon", rpm:"git-daemon~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-daemon-debuginfo", rpm:"git-daemon-debuginfo~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-debuginfo", rpm:"git-debuginfo~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-debugsource", rpm:"git-debugsource~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-email", rpm:"git-email~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-gui", rpm:"git-gui~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-p4", rpm:"git-p4~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-svn", rpm:"git-svn~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-svn-debuginfo", rpm:"git-svn-debuginfo~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-web", rpm:"git-web~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitk", rpm:"gitk~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-doc", rpm:"git-doc~2.26.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
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