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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0187");
  script_cve_id("CVE-2019-11005", "CVE-2019-11006", "CVE-2019-11007", "CVE-2019-11008", "CVE-2019-11009", "CVE-2019-11010", "CVE-2019-11473", "CVE-2019-11474", "CVE-2019-11505", "CVE-2019-11506");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2019-0187)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0187");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0187.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24766");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2019-04/msg00188.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphicsmagick' package(s) announced via the MGASA-2019-0187 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated graphicsmagick packages fix security vulnerabilities

In GraphicsMagick 1.4 snapshot-20190322 Q8, there is a stack-based buffer
overflow in the function SVGStartElement of coders/svg.c, which allows
remote attackers to cause a denial of service (application crash) or
possibly have unspecified other impact via a quoted font family value.
(CVE-2019-11005)

In GraphicsMagick 1.4 snapshot-20190322 Q8, there is a heap-based buffer
over-read in the function ReadMIFFImage of coders/miff.c, which allows
attackers to cause a denial of service or information disclosure via an
RLE packet. (CVE-2019-11006)

In GraphicsMagick 1.4 snapshot-20190322 Q8, there is a heap-based buffer
over-read in the ReadMNGImage function of coders/png.c, which allows
attackers to cause a denial of service or information disclosure via an
image colormap. (CVE-2019-11007)

In GraphicsMagick 1.4 snapshot-20190322 Q8, there is a heap-based buffer
overflow in the function WriteXWDImage of coders/xwd.c, which allows
remote attackers to cause a denial of service (application crash) or
possibly have unspecified other impact via a crafted image file.
(CVE-2019-11008)

In GraphicsMagick 1.4 snapshot-20190322 Q8, there is a heap-based buffer
over-read in the function ReadXWDImage of coders/xwd.c, which allows
attackers to cause a denial of service or information disclosure via a
crafted image file. (CVE-2019-11009)

In GraphicsMagick 1.4 snapshot-20190322 Q8, there is a memory leak in the
function ReadMPCImage of coders/mpc.c, which allows attackers to cause a
denial of service via a crafted image file. (CVE-2019-11010)

coders/xwd.c in GraphicsMagick 1.3.31 allows attackers to cause a denial
of service (out-of-bounds read and application crash) by crafting an XWD
image file, a different vulnerability than CVE-2019-11008 and
CVE-2019-11009. (CVE-2019-11473)

coders/xwd.c in GraphicsMagick 1.3.31 allows attackers to cause a denial
of service (floating-point exception and application crash) by crafting
an XWD image file, a different vulnerability than CVE-2019-11008 and
CVE-2019-11009. (CVE-2019-11474)

In GraphicsMagick from version 1.3.8 to 1.4 snapshot-20190403 Q8, there
is a heap-based buffer overflow in the function WritePDBImage of
coders/pdb.c, which allows an attacker to cause a denial of service or
possibly have unspecified other impact via a crafted image file. This is
related to MagickBitStreamMSBWrite in magick/bit_stream.c.
(CVE-2019-11505)

In GraphicsMagick from version 1.3.30 to 1.4 snapshot-20190403 Q8, there
is a heap-based buffer overflow in the function WriteMATLABImage of
coders/mat.c, which allows an attacker to cause a denial of service or
possibly have unspecified other impact via a crafted image file. This is
related to ExportRedQuantumType in magick/export.c. (CVE-2019-11506)");

  script_tag(name:"affected", value:"'graphicsmagick' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"graphicsmagick", rpm:"graphicsmagick~1.3.31~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphicsmagick-doc", rpm:"graphicsmagick-doc~1.3.31~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagick++12", rpm:"lib64graphicsmagick++12~1.3.31~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagick-devel", rpm:"lib64graphicsmagick-devel~1.3.31~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagick3", rpm:"lib64graphicsmagick3~1.3.31~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagickwand2", rpm:"lib64graphicsmagickwand2~1.3.31~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagick++12", rpm:"libgraphicsmagick++12~1.3.31~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagick-devel", rpm:"libgraphicsmagick-devel~1.3.31~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagick3", rpm:"libgraphicsmagick3~1.3.31~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagickwand2", rpm:"libgraphicsmagickwand2~1.3.31~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Graphics-Magick", rpm:"perl-Graphics-Magick~1.3.31~1.5.mga6", rls:"MAGEIA6"))) {
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
