# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2022.291.01");
  script_cve_id("CVE-2022-39253", "CVE-2022-39260");
  script_tag(name:"creation_date", value:"2022-10-19 04:52:12 +0000 (Wed, 19 Oct 2022)");
  script_version("2022-10-19T04:52:12+0000");
  script_tag(name:"last_modification", value:"2022-10-19 04:52:12 +0000 (Wed, 19 Oct 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2022-291-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(14\.0|14\.1|14\.2|15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2022-291-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2022&m=slackware-security.542781");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git' package(s) announced via the SSA:2022-291-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New git packages are available for Slackware 14.0, 14.1, 14.2, 15.0,
and -current to fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/git-2.35.5-i586-1_slack15.0.txz: Upgraded.
 This release fixes two security issues:
 * CVE-2022-39253:
 When relying on the `--local` clone optimization, Git dereferences
 symbolic links in the source repository before creating hardlinks
 (or copies) of the dereferenced link in the destination repository.
 This can lead to surprising behavior where arbitrary files are
 present in a repository's `$GIT_DIR` when cloning from a malicious
 repository.
 Git will no longer dereference symbolic links via the `--local`
 clone mechanism, and will instead refuse to clone repositories that
 have symbolic links present in the `$GIT_DIR/objects` directory.
 Additionally, the value of `protocol.file.allow` is changed to be
 'user' by default.
 * CVE-2022-39260:
 An overly-long command string given to `git shell` can result in
 overflow in `split_cmdline()`, leading to arbitrary heap writes and
 remote code execution when `git shell` is exposed and the directory
 `$HOME/git-shell-commands` exists.
 `git shell` is taught to refuse interactive commands that are
 longer than 4MiB in size. `split_cmdline()` is hardened to reject
 inputs larger than 2GiB.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'git' package(s) on Slackware 14.0, Slackware 14.1, Slackware 14.2, Slackware 15.0, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK14.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"git", ver:"2.30.6-i486-1_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"git", ver:"2.30.6-x86_64-1_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK14.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"git", ver:"2.30.6-i486-1_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"git", ver:"2.30.6-x86_64-1_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK14.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"git", ver:"2.30.6-i586-1_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"git", ver:"2.30.6-x86_64-1_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"git", ver:"2.35.5-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"git", ver:"2.35.5-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"git", ver:"2.38.1-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"git", ver:"2.38.1-x86_64-1", rls:"SLKcurrent"))) {
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
