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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0170");
  script_cve_id("CVE-2017-2887");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-28 15:42:00 +0000 (Tue, 28 Jul 2020)");

  script_name("Mageia: Security Advisory (MGASA-2018-0170)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0170");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0170.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22650");
  script_xref(name:"URL", value:"https://www.suse.com/security/cve/CVE-2017-2887/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SDL_image, SDL_image, mingw-SDL_image' package(s) announced via the MGASA-2018-0170 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An exploitable buffer overflow vulnerability exists in the XCF property
handling functionality of SDL_image 2.0.1. A specially crafted xcf file
can cause a stack-based buffer overflow resulting in potential code
execution. An attacker can provide a specially crafted XCF file to
trigger this vulnerability (CVE-2017-2887).");

  script_tag(name:"affected", value:"'SDL_image, SDL_image, mingw-SDL_image' package(s) on Mageia 5, Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"SDL_image", rpm:"SDL_image~1.2.12~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64SDL_image-devel", rpm:"lib64SDL_image-devel~1.2.12~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64SDL_image1.2_0", rpm:"lib64SDL_image1.2_0~1.2.12~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64SDL_image1.2_0-test", rpm:"lib64SDL_image1.2_0-test~1.2.12~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL_image-devel", rpm:"libSDL_image-devel~1.2.12~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL_image1.2_0", rpm:"libSDL_image1.2_0~1.2.12~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL_image1.2_0-test", rpm:"libSDL_image1.2_0-test~1.2.12~8.1.mga5", rls:"MAGEIA5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"SDL_image", rpm:"SDL_image~1.2.12~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64SDL_image-devel", rpm:"lib64SDL_image-devel~1.2.12~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64SDL_image1.2_0", rpm:"lib64SDL_image1.2_0~1.2.12~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64SDL_image1.2_0-test", rpm:"lib64SDL_image1.2_0-test~1.2.12~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL_image-devel", rpm:"libSDL_image-devel~1.2.12~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL_image1.2_0", rpm:"libSDL_image1.2_0~1.2.12~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL_image1.2_0-test", rpm:"libSDL_image1.2_0-test~1.2.12~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-SDL_image", rpm:"mingw-SDL_image~1.2.12~13.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-SDL_image", rpm:"mingw32-SDL_image~1.2.12~13.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-SDL_image", rpm:"mingw64-SDL_image~1.2.12~13.1.mga6", rls:"MAGEIA6"))) {
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
