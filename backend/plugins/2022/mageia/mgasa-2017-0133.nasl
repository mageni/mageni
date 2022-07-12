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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0133");
  script_cve_id("CVE-2016-10217", "CVE-2016-10218", "CVE-2016-10219", "CVE-2016-10220", "CVE-2016-7976", "CVE-2016-7977", "CVE-2016-7978", "CVE-2016-7979", "CVE-2016-8602", "CVE-2016-9601", "CVE-2017-5951", "CVE-2017-7207", "CVE-2017-8291");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0133)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0133");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0133.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19542");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/10/05/15");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/IJ3D6O5XHLO4UJVJETVCWPIWWWV6LQUE/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript, gutenprint, libspectre' package(s) announced via the MGASA-2017-0133 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various userparams in Ghostscript allow %pipe% in paths, allowing remote
shell command execution (CVE-2016-7976).

The .libfile function in Ghostscript doesn't check PermitFileReading
array, allowing remote file disclosure (CVE-2016-7977).

Reference leak in the .setdevice function in Ghostscript allows
use-after-free and remote code execution (CVE-2016-7978).

Type confusion in the .initialize_dsc_parser function in Ghostscript
allows remote code execution (CVE-2016-7979).

The .sethalftone5 function in psi/zht2.c in Ghostscript before 9.21
allows remote attackers to cause a denial of service (application crash)
or possibly execute arbitrary code via a crafted Postscript document
that calls .sethalftone5 with an empty operand stack (CVE-2016-8602).

A heap based buffer overflow was found in the ghostscript
jbig2_decode_gray_scale_image() function used to decode halftone segments
in a JBIG2 image. A document (PostScript or PDF) with an embedded,
specially crafted, jbig2 image could trigger a segmentation fault in
ghostscript (CVE-2016-9601).

The pdf14_open function in base/gdevp14.c in Ghostscript 9.20 allows
remote attackers to cause a denial of service (use-after-free and
application crash) via a crafted file that is mishandled in the color
management module (CVE-2016-10217).

The pdf14_pop_transparency_group function in base/gdevp14.c in the PDF
Transparency module in Ghostscript 9.20 allows remote attackers to cause
a denial of service (NULL pointer dereference and application crash) via
a crafted file (CVE-2016-10218).

The intersect function in base/gxfill.c in Ghostscript 9.20 allows
remote attackers to cause a denial of service (divide-by-zero error and
application crash) via a crafted file (CVE-2016-10219).

The gs_makewordimagedevice function in base/gsdevmem.c in Ghostscript
9.20 allows remote attackers to cause a denial of service (NULL pointer
dereference and application crash) via a crafted file that is mishandled
in the PDF Transparency module (CVE-2016-10220).

The mem_get_bits_rectangle function in base/gdevmem.c in Ghostscript
9.20 allows remote attackers to cause a denial of service (NULL pointer
dereference and application crash) via a crafted file (CVE-2017-5951).

The mem_get_bits_rectangle function in Ghostscript 9.20 allows remote
attackers to cause a denial of service (NULL pointer dereference) via a
crafted PostScript document (CVE-2017-7207).

Ghostscript through 2017-04-26 allows -dSAFER bypass and remote command
execution via .rsdparams type confusion with a '/OutputFile (%pipe%'
substring in a crafted .eps document that is an input to the gs program
(CVE-2017-8291).");

  script_tag(name:"affected", value:"'ghostscript, gutenprint, libspectre' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-X", rpm:"ghostscript-X~9.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-common", rpm:"ghostscript-common~9.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~9.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-dvipdf", rpm:"ghostscript-dvipdf~9.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-module-X", rpm:"ghostscript-module-X~9.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gutenprint", rpm:"gutenprint~5.2.10~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gutenprint-common", rpm:"gutenprint-common~5.2.10~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gutenprint-cups", rpm:"gutenprint-cups~5.2.10~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gutenprint-escputil", rpm:"gutenprint-escputil~5.2.10~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gutenprint-foomatic", rpm:"gutenprint-foomatic~5.2.10~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gutenprint-gimp2", rpm:"gutenprint-gimp2~5.2.10~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs-devel", rpm:"lib64gs-devel~9.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs9", rpm:"lib64gs9~9.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gutenprint2", rpm:"lib64gutenprint2~5.2.10~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gutenprint2-devel", rpm:"lib64gutenprint2-devel~5.2.10~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gutenprintui2_1", rpm:"lib64gutenprintui2_1~5.2.10~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gutenprintui2_1-devel", rpm:"lib64gutenprintui2_1-devel~5.2.10~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs-devel", rpm:"lib64ijs-devel~0.35~115.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs1", rpm:"lib64ijs1~0.35~115.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spectre-devel", rpm:"lib64spectre-devel~0.2.7~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spectre1", rpm:"lib64spectre1~0.2.7~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs-devel", rpm:"libgs-devel~9.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs9", rpm:"libgs9~9.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgutenprint2", rpm:"libgutenprint2~5.2.10~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgutenprint2-devel", rpm:"libgutenprint2-devel~5.2.10~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgutenprintui2_1", rpm:"libgutenprintui2_1~5.2.10~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgutenprintui2_1-devel", rpm:"libgutenprintui2_1-devel~5.2.10~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs-devel", rpm:"libijs-devel~0.35~115.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs1", rpm:"libijs1~0.35~115.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspectre", rpm:"libspectre~0.2.7~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspectre-devel", rpm:"libspectre-devel~0.2.7~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspectre1", rpm:"libspectre1~0.2.7~5.1.mga5", rls:"MAGEIA5"))) {
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
