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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0206");
  script_cve_id("CVE-2016-9601", "CVE-2017-7885", "CVE-2017-7975", "CVE-2017-7976");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0206)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0206");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0206.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20565");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3817");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/XWQQMCDLDOZ535O3IKFQZE3VPCWC3HWH/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jbig2dec' package(s) announced via the MGASA-2017-0206 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in the JBIG2 decoder library,
which may lead to lead to denial of service or the execution of arbitrary
code if a malformed image file (usually embedded in a PDF document) is
opened (CVE-2016-9601).

Artifex jbig2dec has a heap-based buffer over-read leading to denial of
service (application crash) because of an integer overflow in the
jbig2_decode_symbol_dict function in jbig2_symbol_dict.c in libjbig2dec.a
during operation on a crafted .jb2 file (CVE-2017-7885).

Artifex jbig2dec allows out-of-bounds writes because of an integer
overflow in the jbig2_build_huffman_table function in jbig2_huffman.c
during operations on a crafted JBIG2 file, leading to a denial of service
(application crash) or possibly execution of arbitrary code
(CVE-2017-7975).

Artifex jbig2dec allows out-of-bounds writes and reads because of an
integer overflow in the jbig2_image_compose function in jbig2_image.c
during operations on a crafted .jb2 file, leading to a denial of service
(application crash) (CVE-2017-7976).");

  script_tag(name:"affected", value:"'jbig2dec' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"jbig2dec", rpm:"jbig2dec~0.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jbig2dec-devel", rpm:"lib64jbig2dec-devel~0.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jbig2dec0", rpm:"lib64jbig2dec0~0.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjbig2dec-devel", rpm:"libjbig2dec-devel~0.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjbig2dec0", rpm:"libjbig2dec0~0.13~1.mga5", rls:"MAGEIA5"))) {
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
