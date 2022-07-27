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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0430");
  script_cve_id("CVE-2017-6196", "CVE-2017-7948", "CVE-2017-8908", "CVE-2017-9216", "CVE-2017-9610", "CVE-2017-9618", "CVE-2017-9619", "CVE-2017-9620", "CVE-2017-9740");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-22 01:29:00 +0000 (Tue, 22 Aug 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0430)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0430");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0430.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22052");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/2QUCMGMEGU4TK3I5424ZFZYFJHEQRF4P/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript, ghostscript' package(s) announced via the MGASA-2017-0430 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple use-after-free vulnerabilities in the gx_image_enum_begin
function in base/gxipixel.c in Ghostscript before
ecceafe3abba2714ef9b432035fe0739d9b1a283 allow remote attackers to cause
a denial of service (application crash) or possibly have unspecified
other impact via a crafted PostScript document. (CVE-2017-6196)

Integer overflow in the mark_curve function in Artifex Ghostscript 9.21
allows remote attackers to cause a denial of service (out-of-bounds
write and application crash) or possibly have unspecified other impact
via a crafted PostScript document. (CVE-2017-7948)

The mark_line_tr function in gxscanc.c in Artifex Ghostscript 9.21
allows remote attackers to cause a denial of service (out-of-bounds
read) via a crafted PostScript document. (CVE-2017-8908)

libjbig2dec.a in Artifex jbig2dec 0.13, as used in MuPDF and
Ghostscript, has a NULL pointer dereference in the jbig2_huffman_get
function in jbig2_huffman.c. For example, the jbig2dec utility will
crash (segmentation fault) when parsing an invalid file.
(CVE-2017-9216)

The xps_load_sfnt_name function in xps/xpsfont.c in Artifex Ghostscript
GhostXPS 9.21 allows remote attackers to cause a denial of service
(heap-based buffer over-read and application crash) or possibly have
unspecified other impact via a crafted document. (CVE-2017-9610)

The xps_load_sfnt_name function in xps/xpsfont.c in Artifex Ghostscript
GhostXPS 9.21 allows remote attackers to cause a denial of service
(buffer overflow and application crash) or possibly have unspecified
other impact via a crafted document. (CVE-2017-9618)

The xps_true_callback_glyph_name function in xps/xpsttf.c in Artifex
Ghostscript GhostXPS 9.21 allows remote attackers to cause a denial of
service (Segmentation Violation and application crash) via a crafted
file. (CVE-2017-9619)

The xps_select_font_encoding function in xps/xpsfont.c in Artifex
Ghostscript GhostXPS 9.21 allows remote attackers to cause a denial of
service (heap-based buffer over-read and application crash) or possibly
have unspecified other impact via a crafted document, related to the
xps_encode_font_char_imp function. (CVE-2017-9620)

The xps_decode_font_char_imp function in xps/xpsfont.c in Artifex
Ghostscript GhostXPS 9.21 allows remote attackers to cause a denial of
service (heap-based buffer over-read and application crash) or possibly
have unspecified other impact via a crafted document. (CVE-2017-9740)");

  script_tag(name:"affected", value:"'ghostscript, ghostscript' package(s) on Mageia 5, Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.22~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-X", rpm:"ghostscript-X~9.22~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-common", rpm:"ghostscript-common~9.22~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~9.22~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-dvipdf", rpm:"ghostscript-dvipdf~9.22~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-module-X", rpm:"ghostscript-module-X~9.22~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs-devel", rpm:"lib64gs-devel~9.22~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs9", rpm:"lib64gs9~9.22~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs-devel", rpm:"lib64ijs-devel~0.35~124.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs1", rpm:"lib64ijs1~0.35~124.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs-devel", rpm:"libgs-devel~9.22~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs9", rpm:"libgs9~9.22~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs-devel", rpm:"libijs-devel~0.35~124.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs1", rpm:"libijs1~0.35~124.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.22~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-X", rpm:"ghostscript-X~9.22~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-common", rpm:"ghostscript-common~9.22~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~9.22~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-dvipdf", rpm:"ghostscript-dvipdf~9.22~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-module-X", rpm:"ghostscript-module-X~9.22~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs-devel", rpm:"lib64gs-devel~9.22~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs9", rpm:"lib64gs9~9.22~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs-devel", rpm:"lib64ijs-devel~0.35~124.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs1", rpm:"lib64ijs1~0.35~124.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs-devel", rpm:"libgs-devel~9.22~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs9", rpm:"libgs9~9.22~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs-devel", rpm:"libijs-devel~0.35~124.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs1", rpm:"libijs1~0.35~124.mga6", rls:"MAGEIA6"))) {
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
