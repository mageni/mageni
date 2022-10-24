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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0386");
  script_cve_id("CVE-2022-38784");
  script_tag(name:"creation_date", value:"2022-10-24 04:53:32 +0000 (Mon, 24 Oct 2022)");
  script_version("2022-10-24T04:53:32+0000");
  script_tag(name:"last_modification", value:"2022-10-24 04:53:32 +0000 (Mon, 24 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-02 21:51:00 +0000 (Fri, 02 Sep 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0386)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0386");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0386.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30805");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/09/02/11");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5224");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5606-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5606-2");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/TQAO6O2XHPQHNW2MWOCJJ4C3YWS2VV4K/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3120");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the MGASA-2022-0386 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Poppler prior to and including 22.08.0 contains an integer overflow in the
JBIG2 decoder (JBIG2Stream::readTextRegionSeg() in JBIGStream.cc).
Processing a specially crafted PDF file or JBIG2 image could lead to a
crash or the execution of arbitrary code. This is similar to the
vulnerability described by CVE-2022-38171 in Xpdf. (CVE-2022-38784)");

  script_tag(name:"affected", value:"'poppler' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-cpp-devel", rpm:"lib64poppler-cpp-devel~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-cpp0", rpm:"lib64poppler-cpp0~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-devel", rpm:"lib64poppler-devel~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-gir0.18", rpm:"lib64poppler-gir0.18~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-glib-devel", rpm:"lib64poppler-glib-devel~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-glib8", rpm:"lib64poppler-glib8~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-qt5-devel", rpm:"lib64poppler-qt5-devel~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-qt5_1", rpm:"lib64poppler-qt5_1~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler105", rpm:"lib64poppler105~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp-devel", rpm:"libpoppler-cpp-devel~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0", rpm:"libpoppler-cpp0~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-devel", rpm:"libpoppler-devel~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-gir0.18", rpm:"libpoppler-gir0.18~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib-devel", rpm:"libpoppler-glib-devel~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8", rpm:"libpoppler-glib8~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-devel", rpm:"libpoppler-qt5-devel~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5_1", rpm:"libpoppler-qt5_1~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler105", rpm:"libpoppler105~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler", rpm:"poppler~20.12.1~1.2.mga8", rls:"MAGEIA8"))) {
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
