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
  script_oid("1.3.6.1.4.1.25623.1.0.854908");
  script_version("2022-08-22T10:11:10+0000");
  script_cve_id("CVE-2021-46790", "CVE-2022-30783", "CVE-2022-30784", "CVE-2022-30785", "CVE-2022-30786", "CVE-2022-30787", "CVE-2022-30788", "CVE-2022-30789");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-08-22 10:11:10 +0000 (Mon, 22 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-09 19:09:00 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2022-08-18 01:05:10 +0000 (Thu, 18 Aug 2022)");
  script_name("openSUSE: Security Advisory for ntfs-3g_ntfsprogs (SUSE-SU-2022:2835-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2835-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CUCIRAD67WWT3IZWCVN25JFFBTDANX5J");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntfs-3g_ntfsprogs'
  package(s) announced via the SUSE-SU-2022:2835-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ntfs-3g_ntfsprogs fixes the following issues:
  Updated to version 2022.5.17 (bsc#1199978):

  - CVE-2022-30783: Fixed an issue where messages between NTFS-3G and the
       kernel could be intercepted when using libfuse-lite.

  - CVE-2022-30784: Fixed a memory exhaustion issue when opening a crafted
       NTFS image.

  - CVE-2022-30785: Fixed a bug where arbitrary memory read and write
       operations could be achieved when using libfuse-lite.

  - CVE-2022-30786: Fixed a memory corruption issue when opening a crafted
       NTFS image.

  - CVE-2022-30787: Fixed an integer underflow which enabled arbitrary
       memory read operations when using libfuse-lite.

  - CVE-2022-30788: Fixed a memory corruption issue when opening a crafted
       NTFS image.

  - CVE-2022-30789: Fixed a memory corruption issue when opening a crafted
       NTFS image.");

  script_tag(name:"affected", value:"'ntfs-3g_ntfsprogs' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g-devel", rpm:"libntfs-3g-devel~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g87", rpm:"libntfs-3g87~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g87-debuginfo", rpm:"libntfs-3g87-debuginfo~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g", rpm:"ntfs-3g~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g-debuginfo", rpm:"ntfs-3g-debuginfo~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g_ntfsprogs-debuginfo", rpm:"ntfs-3g_ntfsprogs-debuginfo~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g_ntfsprogs-debugsource", rpm:"ntfs-3g_ntfsprogs-debugsource~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs", rpm:"ntfsprogs~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs-debuginfo", rpm:"ntfsprogs-debuginfo~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs-extra", rpm:"ntfsprogs-extra~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs-extra-debuginfo", rpm:"ntfsprogs-extra-debuginfo~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g-devel", rpm:"libntfs-3g-devel~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g87", rpm:"libntfs-3g87~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g87-debuginfo", rpm:"libntfs-3g87-debuginfo~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g", rpm:"ntfs-3g~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g-debuginfo", rpm:"ntfs-3g-debuginfo~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g_ntfsprogs-debuginfo", rpm:"ntfs-3g_ntfsprogs-debuginfo~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g_ntfsprogs-debugsource", rpm:"ntfs-3g_ntfsprogs-debugsource~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs", rpm:"ntfsprogs~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs-debuginfo", rpm:"ntfsprogs-debuginfo~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs-extra", rpm:"ntfsprogs-extra~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs-extra-debuginfo", rpm:"ntfsprogs-extra-debuginfo~2022.5.17~150000.3.11.1", rls:"openSUSELeap15.3"))) {
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
