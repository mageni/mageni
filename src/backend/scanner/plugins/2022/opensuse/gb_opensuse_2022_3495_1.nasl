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
  script_oid("1.3.6.1.4.1.25623.1.0.822648");
  script_version("2022-10-14T08:45:32+0000");
  script_cve_id("CVE-2019-1352", "CVE-2022-24765", "CVE-2022-29187");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-10-14 08:45:32 +0000 (Fri, 14 Oct 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-28 01:15:00 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"creation_date", value:"2022-10-05 01:02:57 +0000 (Wed, 05 Oct 2022)");
  script_name("openSUSE: Security Advisory for libgit2 (SUSE-SU-2022:3495-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3495-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Y2LS4XTLFNHTR5UP53YEFITFCIBUGFUT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgit2'
  package(s) announced via the SUSE-SU-2022:3495-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libgit2 fixes the following issues:

  - Fixed DoS by oob write in constructed commit object with a very large
       number of parents (bsc#1158981).

  - CVE-2019-1352: Fixed git on Windows being unaware of NTFS Alternate Data
       Streams (bnc#1158790).

  - CVE-2022-24765: Fixed potential command injection via git worktree
       (bsc#1198234).

  - CVE-2022-29187: Fixed incomplete fix for CVE-2022-24765 (bsc#1201431).");

  script_tag(name:"affected", value:"'libgit2' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"libgit2-26", rpm:"libgit2-26~0.26.8~150000.3.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2-26-debuginfo", rpm:"libgit2-26-debuginfo~0.26.8~150000.3.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2-26-32bit", rpm:"libgit2-26-32bit~0.26.8~150000.3.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2-26-32bit-debuginfo", rpm:"libgit2-26-32bit-debuginfo~0.26.8~150000.3.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"libgit2-26", rpm:"libgit2-26~0.26.8~150000.3.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2-26-debuginfo", rpm:"libgit2-26-debuginfo~0.26.8~150000.3.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2-26-32bit", rpm:"libgit2-26-32bit~0.26.8~150000.3.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2-26-32bit-debuginfo", rpm:"libgit2-26-32bit-debuginfo~0.26.8~150000.3.15.1", rls:"openSUSELeap15.3"))) {
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