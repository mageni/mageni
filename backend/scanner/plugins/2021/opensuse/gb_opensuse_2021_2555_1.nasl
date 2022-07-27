# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.854027");
  script_version("2021-08-03T06:52:21+0000");
  script_cve_id("CVE-2021-21300");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-03 10:35:54 +0000 (Tue, 03 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-07-30 03:02:03 +0000 (Fri, 30 Jul 2021)");
  script_name("openSUSE: Security Advisory for git (openSUSE-SU-2021:2555-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:2555-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LNQQ262LF4R2GIO7S7J6NRAUDKV7VGPB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git'
  package(s) announced via the openSUSE-SU-2021:2555-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for git fixes the following issues:

     Update from version 2.26.2 to version 2.31.1 (jsc#SLE-18152)

     Security fixes:

  - CVE-2021-21300: On case-insensitive file systems with support for
       symbolic links, if Git is configured globally to apply delay-capable
       clean/smudge filters (such as Git LFS), Git could run remote code during
       a clone. (bsc#1183026)

     Non security changes:

  - Add `sysusers` file to create `git-daemon` user.

  - Remove `perl-base` and `openssh-server` dependency on `git-core`and
       provide a `perl-Git` package. (jsc#SLE-17838)

  - `fsmonitor` bug fixes

  - Fix `git bisect` to take an annotated tag as a good/bad endpoint

  - Fix a corner case in `git mv` on case insensitive systems

  - Require only `openssh-clients` where possible (like Tumbleweed or SUSE
       Linux Enterprise  = 15 SP3). (bsc#1183580)

  - Drop `rsync` requirement, not necessary anymore.

  - Use of `pack-redundant` command is discouraged and will trigger a
       warning. The replacement is `repack -d`.

  - The `--format=%(trailers)` mechanism gets enhanced to make it easier to
       design output for machine consumption.

  - No longer give message to choose between rebase or merge upon pull if
       the history `fast-forwards`.

  - The configuration variable `core.abbrev` can be set to `no` to force no
       abbreviation regardless of the hash algorithm

  - `git rev-parse` can be explicitly told to give output as absolute or
       relative path with the `--path-format=(absoluterelative)` option.

  - Bash completion update to make it easier for end-users to add completion
       for their custom `git` subcommands.

  - `git maintenance` learned to drive scheduled maintenance on platforms
       whose native scheduling methods are not &#x27 cron&#x27 .

  - After expiring a reflog and making a single commit, the reflog for the
       branch would record a single entry that knows both `@{0}` and `@{1}`,
       but we failed to answer 'what commit were we on?', i.e. `@{1}`

  - `git bundle` learns `--stdin` option to read its refs from the standard
       input. Also, it now does not lose refs when they point at the same
       object.

  - `git log` learned a new `--diff-merges= how ` option.

  - `git ls-files` can and does show multiple entries when the index is
       unmerged, which is a source for confusion unless `-s/-u` option is in
       use.  A new option `--deduplicate` has been introduced.

  - `git worktree list` now annotates worktrees as prunable, shows locked
       and prunable att ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'git' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"git", rpm:"git~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-arch", rpm:"git-arch~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-core-debuginfo", rpm:"git-core-debuginfo~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-credential-gnome-keyring", rpm:"git-credential-gnome-keyring~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-credential-gnome-keyring-debuginfo", rpm:"git-credential-gnome-keyring-debuginfo~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-credential-libsecret", rpm:"git-credential-libsecret~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-credential-libsecret-debuginfo", rpm:"git-credential-libsecret-debuginfo~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-cvs", rpm:"git-cvs~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-daemon", rpm:"git-daemon~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-daemon-debuginfo", rpm:"git-daemon-debuginfo~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-debuginfo", rpm:"git-debuginfo~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-debugsource", rpm:"git-debugsource~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-email", rpm:"git-email~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-gui", rpm:"git-gui~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-p4", rpm:"git-p4~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-svn", rpm:"git-svn~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-web", rpm:"git-web~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitk", rpm:"gitk~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Git", rpm:"perl-Git~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-doc", rpm:"git-doc~2.31.1~10.3.1", rls:"openSUSELeap15.3"))) {
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