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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0454");
  script_cve_id("CVE-2017-12122", "CVE-2017-14440", "CVE-2017-14441", "CVE-2017-14442", "CVE-2017-14448", "CVE-2017-14449", "CVE-2017-14450", "CVE-2018-3837", "CVE-2018-3838", "CVE-2018-3839", "CVE-2018-3977");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-28 15:42:00 +0000 (Tue, 28 Jul 2020)");

  script_name("Mageia: Security Advisory (MGASA-2018-0454)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0454");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0454.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22769");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2017-0488");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2017-0489");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2017-0490");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2017-0491");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2017-0497");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2017-0498");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2017-0499");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2018-0519");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2018-0520");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2018-0521");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2018-0645");
  script_xref(name:"URL", value:"https://hg.libsdl.org/SDL/file/8feb5da6f2fb/WhatsNew.txt");
  script_xref(name:"URL", value:"https://www.libsdl.org/projects/SDL_image/");
  script_xref(name:"URL", value:"https://www.libsdl.org/projects/SDL_mixer/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-SDL2, mingw-SDL2_image, mingw-SDL2_mixer, sdl2, sdl2_image, sdl2_mixer' package(s) announced via the MGASA-2018-0454 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes various security vulnerabilities affecting the
SDL2_image library, listed below. The fixes are provided in SDL2_image
2.0.4, which depends on SDL2 2.0.8 or later. As such, the SDL2 and
SDL2_mixer libraries are also updated to their current stable releases,
providing various bug fixes and features.

The security vulnerabilities fixed in this update are the following:

An exploitable code execution vulnerability exists in the ILBM image
rendering functionality of SDL2_image-2.0.2. A specially crafted ILBM
image can cause a heap overflow resulting in code execution. An attacker
can display a specially crafted image to trigger this vulnerability.
(TALOS-2017-0488, CVE-2017-12122)

An exploitable code execution vulnerability exists in the ILBM image
rendering functionality of SDL2_image-2.0.2. A specially crafted ILBM
image can cause a stack overflow resulting in code execution. An
attacker can display a specially crafted image to trigger this
vulnerability. (TALOS-2017-0489, CVE-2017-14440)

An exploitable code execution vulnerability exists in the ICO image
rendering functionality of SDL2_image-2.0.2. A specially crafted ICO
image can cause an integer overflow, cascading to a heap overflow
resulting in code execution. An attacker can display a specially crafted
image to trigger this vulnerability. (TALOS-2017-0490, CVE-2017-14441)

An exploitable code execution vulnerability exists in the BMP image
rendering functionality of SDL2_image-2.0.2. A specially crafted BMP
image can cause a stack overflow resulting in code execution. An
attacker can display a specially crafted image to trigger this
vulnerability. (TALOS-2017-0491, CVE-2017-14442)

An exploitable code execution vulnerability exists in the XCF image
rendering functionality of SDL2_image-2.0.2. A specially crafted XCF
image can cause a heap overflow resulting in code execution. An
attacker can display a specially crafted image to trigger this
vulnerability. (TALOS-2017-0497, CVE-2017-14448)

A double-Free vulnerability exists in the XCF image rendering
functionality of SDL2_image-2.0.2. A specially crafted XCF image can
cause a Double-Free situation to occur. An attacker can display a
specially crafted image to trigger this vulnerability.
(TALOS-2017-0498, CVE-2017-14449)

A buffer overflow vulnerability exists in the GIF image parsing
functionality of SDL2_image-2.0.2. A specially crafted GIF image can
lead to a buffer overflow on a global section. An attacker can display
an image to trigger this vulnerability. (TALOS-2017-0499,
CVE-2017-14450)

An exploitable information disclosure vulnerability exists in the PCX
image rendering functionality of SDL2_image-2.0.2. A specially crafted
PCX image can cause an out-of-bounds read on the heap, resulting in
information disclosure. An attacker can display a specially crafted
image to trigger this vulnerability. (TALOS-2018-0519, CVE-2018-3837)

An ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'mingw-SDL2, mingw-SDL2_image, mingw-SDL2_mixer, sdl2, sdl2_image, sdl2_mixer' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2.0-devel", rpm:"lib64sdl2.0-devel~2.0.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2.0-static-devel", rpm:"lib64sdl2.0-static-devel~2.0.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2.0_0", rpm:"lib64sdl2.0_0~2.0.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2_image-devel", rpm:"lib64sdl2_image-devel~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2_image-static-devel", rpm:"lib64sdl2_image-static-devel~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2_image2.0_0", rpm:"lib64sdl2_image2.0_0~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2_image2.0_0-test", rpm:"lib64sdl2_image2.0_0-test~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2_mixer-devel", rpm:"lib64sdl2_mixer-devel~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2_mixer-static-devel", rpm:"lib64sdl2_mixer-static-devel~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2_mixer2.0_0", rpm:"lib64sdl2_mixer2.0_0~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2.0-devel", rpm:"libsdl2.0-devel~2.0.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2.0-static-devel", rpm:"libsdl2.0-static-devel~2.0.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2.0_0", rpm:"libsdl2.0_0~2.0.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2_image-devel", rpm:"libsdl2_image-devel~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2_image-static-devel", rpm:"libsdl2_image-static-devel~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2_image2.0_0", rpm:"libsdl2_image2.0_0~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2_image2.0_0-test", rpm:"libsdl2_image2.0_0-test~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2_mixer-devel", rpm:"libsdl2_mixer-devel~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2_mixer-static-devel", rpm:"libsdl2_mixer-static-devel~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2_mixer2.0_0", rpm:"libsdl2_mixer2.0_0~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-SDL2", rpm:"mingw-SDL2~2.0.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-SDL2_image", rpm:"mingw-SDL2_image~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-SDL2_mixer", rpm:"mingw-SDL2_mixer~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-SDL2", rpm:"mingw32-SDL2~2.0.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-SDL2-static", rpm:"mingw32-SDL2-static~2.0.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-SDL2_image", rpm:"mingw32-SDL2_image~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-SDL2_mixer", rpm:"mingw32-SDL2_mixer~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-SDL2", rpm:"mingw64-SDL2~2.0.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-SDL2-static", rpm:"mingw64-SDL2-static~2.0.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-SDL2_image", rpm:"mingw64-SDL2_image~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-SDL2_mixer", rpm:"mingw64-SDL2_mixer~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sdl2", rpm:"sdl2~2.0.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sdl2-docs", rpm:"sdl2-docs~2.0.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sdl2_image", rpm:"sdl2_image~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sdl2_mixer", rpm:"sdl2_mixer~2.0.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sdl2_mixer-player", rpm:"sdl2_mixer-player~2.0.4~1.mga6", rls:"MAGEIA6"))) {
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
