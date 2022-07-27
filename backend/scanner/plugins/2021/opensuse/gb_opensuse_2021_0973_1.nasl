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
  script_oid("1.3.6.1.4.1.25623.1.0.853932");
  script_version("2021-07-23T08:38:39+0000");
  script_cve_id("CVE-2020-16044", "CVE-2021-21118", "CVE-2021-21119", "CVE-2021-21120", "CVE-2021-21121", "CVE-2021-21122", "CVE-2021-21123", "CVE-2021-21125", "CVE-2021-21126", "CVE-2021-21127", "CVE-2021-21128", "CVE-2021-21129", "CVE-2021-21130", "CVE-2021-21131", "CVE-2021-21132", "CVE-2021-21135", "CVE-2021-21137", "CVE-2021-21140", "CVE-2021-21141", "CVE-2021-21145", "CVE-2021-21146", "CVE-2021-21147", "CVE-2021-21148", "CVE-2021-21149", "CVE-2021-21150", "CVE-2021-21152", "CVE-2021-21153", "CVE-2021-21156", "CVE-2021-21157");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-26 10:31:37 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-13 03:03:44 +0000 (Tue, 13 Jul 2021)");
  script_name("openSUSE: Security Advisory for libqt5-qtwebengine (openSUSE-SU-2021:0973-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0973-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5TAIJROLXEDDASYPE5FNK2OGKN4IAJT5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt5-qtwebengine'
  package(s) announced via the openSUSE-SU-2021:0973-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libqt5-qtwebengine fixes the following issues:

     Update to version 5.15.3

     CVE fixes backported in chromium updates:

  - CVE-2020-16044: Use after free in WebRTC

  - CVE-2021-21118: Heap buffer overflow in Blink

  - CVE-2021-21119: Use after free in Media

  - CVE-2021-21120: Use after free in WebSQL

  - CVE-2021-21121: Use after free in Omnibox

  - CVE-2021-21122: Use after free in Blink

  - CVE-2021-21123: Insufficient data validation in File System API

  - CVE-2021-21125: Insufficient policy enforcement in File System API

  - CVE-2021-21126: Insufficient policy enforcement in extensions

  - CVE-2021-21127: Insufficient policy enforcement in extensions

  - CVE-2021-21128: Heap buffer overflow in Blink

  - CVE-2021-21129: Insufficient policy enforcement in File System API

  - CVE-2021-21130: Insufficient policy enforcement in File System API

  - CVE-2021-21131: Insufficient policy enforcement in File System API

  - CVE-2021-21132: Inappropriate implementation in DevTools

  - CVE-2021-21135: Inappropriate implementation in Performance API

  - CVE-2021-21137: Inappropriate implementation in DevTools

  - CVE-2021-21140: Uninitialized Use in USB

  - CVE-2021-21141: Insufficient policy enforcement in File System API

  - CVE-2021-21145: Use after free in Fonts

  - CVE-2021-21146: Use after free in Navigation

  - CVE-2021-21147: Inappropriate implementation in Skia

  - CVE-2021-21148: Heap buffer overflow in V8

  - CVE-2021-21149: Stack overflow in Data Transfer

  - CVE-2021-21150: Use after free in Downloads

  - CVE-2021-21152: Heap buffer overflow in Media

  - CVE-2021-21153: Stack overflow in GPU Process

  - CVE-2021-21156: Heap buffer overflow in V8

  - CVE-2021-21157: Use after free in Web Sockets");

  script_tag(name:"affected", value:"'libqt5-qtwebengine' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"libQt5Pdf5", rpm:"libQt5Pdf5~5.15.3~lp152.3.3.4", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Pdf5-debuginfo", rpm:"libQt5Pdf5-debuginfo~5.15.3~lp152.3.3.4", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PdfWidgets5", rpm:"libQt5PdfWidgets5~5.15.3~lp152.3.3.4", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PdfWidgets5-debuginfo", rpm:"libQt5PdfWidgets5-debuginfo~5.15.3~lp152.3.3.4", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtpdf-devel", rpm:"libqt5-qtpdf-devel~5.15.3~lp152.3.3.4", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtpdf-examples", rpm:"libqt5-qtpdf-examples~5.15.3~lp152.3.3.4", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtpdf-examples-debuginfo", rpm:"libqt5-qtpdf-examples-debuginfo~5.15.3~lp152.3.3.4", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtpdf-imports", rpm:"libqt5-qtpdf-imports~5.15.3~lp152.3.3.4", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtpdf-imports-debuginfo", rpm:"libqt5-qtpdf-imports-debuginfo~5.15.3~lp152.3.3.4", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtwebengine", rpm:"libqt5-qtwebengine~5.15.3~lp152.3.3.4", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtwebengine-debuginfo", rpm:"libqt5-qtwebengine-debuginfo~5.15.3~lp152.3.3.4", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtwebengine-debugsource", rpm:"libqt5-qtwebengine-debugsource~5.15.3~lp152.3.3.4", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtwebengine-devel", rpm:"libqt5-qtwebengine-devel~5.15.3~lp152.3.3.4", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtwebengine-devel-debuginfo", rpm:"libqt5-qtwebengine-devel-debuginfo~5.15.3~lp152.3.3.4", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtwebengine-examples", rpm:"libqt5-qtwebengine-examples~5.15.3~lp152.3.3.4", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtwebengine-examples-debuginfo", rpm:"libqt5-qtwebengine-examples-debuginfo~5.15.3~lp152.3.3.4", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtpdf-private-headers-devel", rpm:"libqt5-qtpdf-private-headers-devel~5.15.3~lp152.3.3.4", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtwebengine-private-headers-devel", rpm:"libqt5-qtwebengine-private-headers-devel~5.15.3~lp152.3.3.4", rls:"openSUSELeap15.2"))) {
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