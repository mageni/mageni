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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0362");
  script_cve_id("CVE-2016-3181", "CVE-2016-3182", "CVE-2016-3183", "CVE-2016-4796", "CVE-2016-4797", "CVE-2016-5157", "CVE-2016-7163", "CVE-2016-7445", "CVE-2016-8332");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2016-0362)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0362");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0362.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17536");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/HPMDEUIMHTLKMHELDL4F4HZ7X4Y34JEB/");
  script_xref(name:"URL", value:"https://github.com/uclouvain/openjpeg/blob/master/CHANGELOG.md");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3665");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2016-09/msg00109.html");
  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2016-0193/");
  script_xref(name:"URL", value:"http://www.openjpeg.org/2016/09/28/OpenJPEG-2.1.2-released");
  script_xref(name:"URL", value:"https://github.com/uclouvain/openjpeg/blob/openjpeg-2.1/CHANGELOG.md");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript, openjpeg2' package(s) announced via the MGASA-2016-0362 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A specially crafted JPEG2000 image file can force Out-Of-Bounds Read in
opj_tcd_free_tile() (CVE-2016-3181).

A specially crafted JPEG2000 image file can force Heap Corruption in
opj_free() (CVE-2016-3182).

A specially crafted JPEG2000 image file can force Out-Of-Bounds Read in
sycc422_to_rgb() (CVE-2016-3183).

OpenJPEG Heap Buffer Overflow in function color_cmyk_to_rgb() in color.c
(CVE-2016-4796).

OpenJPEG division-by-zero in function opj_tcd_init_tile() in tcd.c
(CVE-2016-4797).

Heap-based buffer overflow in the opj_dwt_interleave_v function in dwt.c
in OpenJPEG allows remote attackers to execute arbitrary code via
crafted coordinate values in JPEG 2000 data (CVE-2016-5157).

Integer overflow in the opj_pi_create_decode function in pi.c in
OpenJPEG allows remote attackers to execute arbitrary code via a crafted
JP2 file, which triggers an out-of-bounds read or write (CVE-2016-7163).

convert.c in OpenJPEG before 2.1.2 allows remote attackers to cause a
denial of service (NULL pointer dereference and application crash) via
vectors involving the variable s (CVE-2016-7445).

A buffer overflow in OpenJPEG 2.1.1 causes arbitrary code execution when
parsing a crafted image. An exploitable code execution vulnerability
exists in the jpeg2000 image file format parser as implemented in the
OpenJpeg library. A specially crafted jpeg2000 file can cause an out of
bound heap write resulting in heap corruption leading to arbitrary code
execution (CVE-2016-8332).");

  script_tag(name:"affected", value:"'ghostscript, openjpeg2' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.14~3.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-X", rpm:"ghostscript-X~9.14~3.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-common", rpm:"ghostscript-common~9.14~3.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~9.14~3.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-dvipdf", rpm:"ghostscript-dvipdf~9.14~3.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-module-X", rpm:"ghostscript-module-X~9.14~3.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs-devel", rpm:"lib64gs-devel~9.14~3.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs9", rpm:"lib64gs9~9.14~3.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs-devel", rpm:"lib64ijs-devel~0.35~107.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs1", rpm:"lib64ijs1~0.35~107.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openjp2_7", rpm:"lib64openjp2_7~2.1.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openjpeg2-devel", rpm:"lib64openjpeg2-devel~2.1.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs-devel", rpm:"libgs-devel~9.14~3.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs9", rpm:"libgs9~9.14~3.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs-devel", rpm:"libijs-devel~0.35~107.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs1", rpm:"libijs1~0.35~107.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2_7", rpm:"libopenjp2_7~2.1.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjpeg2-devel", rpm:"libopenjpeg2-devel~2.1.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.1.2~1.mga5", rls:"MAGEIA5"))) {
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
