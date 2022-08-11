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
  script_oid("1.3.6.1.4.1.25623.1.0.854651");
  script_version("2022-05-23T12:36:28+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-05-23 12:36:28 +0000 (Mon, 23 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-17 12:07:26 +0000 (Tue, 17 May 2022)");
  script_name("openSUSE: Security Advisory for libsolv, (SUSE-SU-2022:1157-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1157-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5MLPR5DBMV4ALDUU5N7XY34TRSTXHWPY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsolv, '
  package(s) announced via the SUSE-SU-2022:1157-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libsolv, libzypp, zypper fixes the following issues:
  Security relevant fix:

  - Harden package signature checks (bsc#1184501).
  libsolv update to 0.7.22:

  - reworked choice rule generation to cover more usecases

  - support SOLVABLE_PREREQ_IGNOREINST in the ordering code (bsc#1196514)

  - support parsing of Debian's Multi-Arch indicator

  - fix segfault on conflict resolution when using bindings

  - fix split provides not working if the update includes a forbidden vendor
       change

  - support strict repository priorities new solver flag:
       SOLVER_FLAG_STRICT_REPO_PRIORITY

  - support zstd compressed control files in debian packages

  - add an ifdef allowing to rename Solvable dependency members ('requires'
       is a keyword in C++20)

  - support setting/reading userdata in solv files new functions:
       repowriter_set_userdata, solv_read_userdata

  - support queying of the custom vendor check function new function:
       pool_get_custom_vendorcheck

  - support solv files with an idarray block

  - allow accessing the toolversion at runtime
  libzypp update to 17.30.0:

  - ZConfig: Update solver settings if target changes (bsc#1196368)

  - Fix possible hang in singletrans mode (bsc#1197134)

  - Do 2 retries if mount is still busy.

  - Fix package signature check (bsc#1184501) Pay attention that header and
       payload are secured by a valid signature and report more detailed which
       signature is missing.

  - Retry umount if device is busy (bsc#1196061, closes #381) A previously
       released ISO image may need a bit more time to release it's loop device.
       So we wait a bit and retry.

  - Fix serializing/deserializing type mismatch in zypp-rpm protocol
       (bsc#1196925)

  - Fix handling of ISO media in releaseAll (bsc#1196061)

  - Hint on common ptf resolver conflicts (bsc#1194848)

  - Hint on ptf  patch resolver conflicts (bsc#1194848)
  zypper update to 1.14.52:

  - info: print the packages upstream URL if available (fixes #426)

  - info: Fix SEGV with not installed PTFs (bsc#1196317)

  - Don't prevent less restrictive umasks (bsc#1195999)");

  script_tag(name:"affected", value:"'libsolv, ' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsolv-debuginfo", rpm:"libsolv-debuginfo~0.7.22~150200.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-debugsource", rpm:"libsolv-debugsource~0.7.22~150200.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-demo", rpm:"libsolv-demo~0.7.22~150200.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-demo-debuginfo", rpm:"libsolv-demo-debuginfo~0.7.22~150200.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-devel", rpm:"libsolv-devel~0.7.22~150200.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-devel-debuginfo", rpm:"libsolv-devel-debuginfo~0.7.22~150200.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-tools", rpm:"libsolv-tools~0.7.22~150200.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-tools-debuginfo", rpm:"libsolv-tools-debuginfo~0.7.22~150200.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp", rpm:"libzypp~17.30.0~150200.36.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-debuginfo", rpm:"libzypp-debuginfo~17.30.0~150200.36.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-debugsource", rpm:"libzypp-debugsource~17.30.0~150200.36.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-devel", rpm:"libzypp-devel~17.30.0~150200.36.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-devel-doc", rpm:"libzypp-devel-doc~17.30.0~150200.36.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-solv", rpm:"perl-solv~0.7.22~150200.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-solv-debuginfo", rpm:"perl-solv-debuginfo~0.7.22~150200.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-solv", rpm:"python-solv~0.7.22~150200.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-solv-debuginfo", rpm:"python-solv-debuginfo~0.7.22~150200.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-solv", rpm:"python3-solv~0.7.22~150200.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-solv-debuginfo", rpm:"python3-solv-debuginfo~0.7.22~150200.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-solv", rpm:"ruby-solv~0.7.22~150200.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-solv-debuginfo", rpm:"ruby-solv-debuginfo~0.7.22~150200.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper", rpm:"zypper~1.14.52~150200.30.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-debuginfo", rpm:"zypper-debuginfo~1.14.52~150200.30.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-debugsource", rpm:"zypper-debugsource~1.14.52~150200.30.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-aptitude", rpm:"zypper-aptitude~1.14.52~150200.30.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-log", rpm:"zypper-log~1.14.52~150200.30.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-needs-restarting", rpm:"zypper-needs-restarting~1.14.52~150200.30.2", rls:"openSUSELeap15.3"))) {
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