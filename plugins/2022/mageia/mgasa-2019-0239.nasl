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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0239");
  script_cve_id("CVE-2010-13616", "CVE-2019-7572", "CVE-2019-7573", "CVE-2019-7574", "CVE-2019-7575", "CVE-2019-7576", "CVE-2019-7577", "CVE-2019-7578", "CVE-2019-7635", "CVE-2019-7636", "CVE-2019-7637", "CVE-2019-7638");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-30 19:52:00 +0000 (Tue, 30 Nov 2021)");

  script_name("Mageia: Security Advisory (MGASA-2019-0239)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(6|7)");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0239");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0239.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24497");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/OHEXXGCOKNICFBDMNVYYDTSDLQ42K5G5/");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/CVE-2019-13616");
  script_xref(name:"URL", value:"https://hg.libsdl.org/SDL/file/bc90ce38f1e2/WhatsNew.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-SDL2, mingw-SDL2, sdl2, sdl2' package(s) announced via the MGASA-2019-0239 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated sdl2 packages fix security vulnerabilities

This release fixes various buffer overflows when parsing or processing
damaged Waveform audio and BMP image files.

- Fix CVE-2019-7572 (a buffer overread in IMA_ADPCM_nibble) (rhbz#1676754)
- Fix CVE-2019-7572 (a buffer overwrite in IMA_ADPCM_nibble) (rhbz#1676754)
- Fix CVE-2019-7573, CVE-2019-7576 (buffer overreads in InitMS_ADPCM)
 (rhbz#1676752, rhbz#1676756)
- Fix CVE-2019-7574 (a buffer overread in IMA_ADPCM_decode) (rhbz#1676750)
- Fix CVE-2019-7575 (a buffer overwrite in MS_ADPCM_decode) (rhbz#1676744)
- Fix CVE-2019-7577 (a buffer overread in MS_ADPCM_decode) (rhbz#1676510)
- Fix CVE-2019-7578 (a buffer overread in InitIMA_ADPCM) (rhbz#1676782)
- Fix CVE-2019-7635 (a buffer overread when blitting a BMP image with pixel
 colors out the palette) (rhbz#1677159)
- Fix CVE-2019-7636, CVE-2019-7638 (buffer overflows when processing BMP
 images with too high number of colors) (rhbz#1677144, rhbz#1677157)
- Fix CVE-2019-7637 (an integer overflow in SDL_CalculatePitch)
 (rhbz#1677152)
- Reject 2, 3, 5, 6, 7-bpp BMP images (rhbz#1677159)
- Fix CVE-2010-13616 (heap-based buffer over-read in BlitNtoN in
 video/SDL_blit_N.c when called from SDL_SoftBlit in video/SDL_blit.c)

The 2.0.10 release also provides various features and bug fixes.");

  script_tag(name:"affected", value:"'mingw-SDL2, mingw-SDL2, sdl2, sdl2' package(s) on Mageia 6, Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2.0-devel", rpm:"lib64sdl2.0-devel~2.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2.0-static-devel", rpm:"lib64sdl2.0-static-devel~2.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2.0_0", rpm:"lib64sdl2.0_0~2.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2.0-devel", rpm:"libsdl2.0-devel~2.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2.0-static-devel", rpm:"libsdl2.0-static-devel~2.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2.0_0", rpm:"libsdl2.0_0~2.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-SDL2", rpm:"mingw-SDL2~2.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-SDL2", rpm:"mingw32-SDL2~2.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-SDL2-static", rpm:"mingw32-SDL2-static~2.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-SDL2", rpm:"mingw64-SDL2~2.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-SDL2-static", rpm:"mingw64-SDL2-static~2.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sdl2", rpm:"sdl2~2.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sdl2-docs", rpm:"sdl2-docs~2.0.10~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2.0-devel", rpm:"lib64sdl2.0-devel~2.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2.0-static-devel", rpm:"lib64sdl2.0-static-devel~2.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2.0_0", rpm:"lib64sdl2.0_0~2.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2.0-devel", rpm:"libsdl2.0-devel~2.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2.0-static-devel", rpm:"libsdl2.0-static-devel~2.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2.0_0", rpm:"libsdl2.0_0~2.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-SDL2", rpm:"mingw-SDL2~2.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-SDL2", rpm:"mingw32-SDL2~2.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-SDL2-static", rpm:"mingw32-SDL2-static~2.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-SDL2", rpm:"mingw64-SDL2~2.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-SDL2-static", rpm:"mingw64-SDL2-static~2.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sdl2", rpm:"sdl2~2.0.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sdl2-docs", rpm:"sdl2-docs~2.0.10~1.mga7", rls:"MAGEIA7"))) {
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
