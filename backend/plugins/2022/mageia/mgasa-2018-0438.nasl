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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0438");
  script_cve_id("CVE-2018-7587", "CVE-2018-7588", "CVE-2018-7589", "CVE-2018-7637", "CVE-2018-7638", "CVE-2018-7639", "CVE-2018-7640", "CVE-2018-7641");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-26 23:15:00 +0000 (Wed, 26 Jun 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0438)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0438");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0438.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23700");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/6Z4EMB7JFEKIYRFRANRNDD7ZIIZP6T4Z/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/OCWBP5ZUZHIZXP7IFUEZIJG7Q3VLJXBV/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cimg, gmic' package(s) announced via the MGASA-2018-0438 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated cimg and gmic packages fix security vulnerabilities:

An issue was discovered in CImg v.220. DoS occurs when loading a crafted
bmp image that triggers an allocation failure in load_bmp in CImg.h
(CVE-2018-7587).

An issue was discovered in CImg v.220. A heap-based buffer over-read in
load_bmp in CImg.h occurs when loading a crafted bmp image (CVE-2018-7588).

An issue was discovered in CImg v.220. A double free in load_bmp in CImg.h
occurs when loading a crafted bmp image (CVE-2018-7589).

An issue was discovered in CImg v.220. A heap-based buffer over-read in
load_bmp in CImg.h occurs when loading a crafted bmp image. This is in a
'16 colors' case, aka case 4 (CVE-2018-7637).

An issue was discovered in CImg v.220. A heap-based buffer over-read in
load_bmp in CImg.h occurs when loading a crafted bmp image. This is in a
'256 colors' case, aka case 8 (CVE-2018-7638).

An issue was discovered in CImg v.220. A heap-based buffer over-read in
load_bmp in CImg.h occurs when loading a crafted bmp image. This is in a
'16 bits colors' case, aka case 16 (CVE-2018-7639).

An issue was discovered in CImg v.220. A heap-based buffer over-read in
load_bmp in CImg.h occurs when loading a crafted bmp image. This is in a
Monochrome case, aka case 1 (CVE-2018-7640).

An issue was discovered in CImg v.220. A heap-based buffer over-read in
load_bmp in CImg.h occurs when loading a crafted bmp image. This is in a
'32 bits colors' case, aka case 32 (CVE-2018-7641).");

  script_tag(name:"affected", value:"'cimg, gmic' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"cimg", rpm:"cimg~2.4.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cimg-devel", rpm:"cimg-devel~2.4.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-plugin-gmic", rpm:"gimp-plugin-gmic~2.4.0~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gmic", rpm:"gmic~2.4.0~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gmic-devel", rpm:"lib64gmic-devel~2.4.0~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gmic2", rpm:"lib64gmic2~2.4.0~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmic-devel", rpm:"libgmic-devel~2.4.0~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmic2", rpm:"libgmic2~2.4.0~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zart", rpm:"zart~2.4.0~1.2.mga6", rls:"MAGEIA6"))) {
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
