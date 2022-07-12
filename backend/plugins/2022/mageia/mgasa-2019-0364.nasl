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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0364");
  script_cve_id("CVE-2019-12217", "CVE-2019-12218", "CVE-2019-12219", "CVE-2019-12220", "CVE-2019-12221", "CVE-2019-12222", "CVE-2019-13616", "CVE-2019-5051", "CVE-2019-5052", "CVE-2019-5057", "CVE-2019-5058", "CVE-2019-5059", "CVE-2019-5060");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-22 22:15:00 +0000 (Mon, 22 Jul 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0364)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0364");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0364.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25767");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2019-09/msg00027.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sdl2_image' package(s) announced via the MGASA-2019-0364 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated sdl2_image packages fix security vulnerabilities:

An exploitable heap-based buffer overflow vulnerability exists when loading
a PCX file in SDL2_image, version 2.0.4. A missing error handler can lead
to a buffer overflow and potential code execution. An attacker can provide
a specially crafted image file to trigger this vulnerability.
(CVE-2019-5051)

An exploitable integer overflow vulnerability exists when loading a PCX
file in SDL2_image 2.0.4. A specially crafted file can cause an integer
overflow, resulting in too little memory being allocated, which can lead
to a buffer overflow and potential code execution. (CVE-2019-5052)

An exploitable code execution vulnerability exists in the PCX image
rendering functionality of SDL2_image 2.0.4. A specially crafted PCX image
can cause a heap overflow, resulting in code execution. An attacker can
display a specially crafted image to trigger this vulnerability.
(CVE-2019-5057)

An exploitable code execution vulnerability exists in the XCF image
rendering functionality of SDL2_image 2.0.4. A specially crafted XCF
image can cause a heap overflow, resulting in code execution.
(CVE-2019-5058)

An exploitable code execution vulnerability exists in the XPM image
rendering functionality of SDL2_image 2.0.4. A specially crafted XPM image
can cause an integer overflow, allocating too small of a buffer. This
buffer can then be written out of bounds resulting in a heap overflow,
ultimately ending in code execution. (CVE-2019-5059)

An exploitable code execution vulnerability exists in the XPM image
rendering function of SDL2_image 2.0.4. A specially crafted XPM image
can cause an integer overflow in the colorhash function, allocating too
small of a buffer. This buffer can then be written out of bounds,
resulting in a heap overflow, ultimately ending in code execution.
(CVE-2019-5060)

An issue was discovered in libSDL2.a in Simple DirectMedia Layer (SDL)
2.0.9 when used in conjunction with libSDL2_image.a in SDL2_image 2.0.4.
There is a NULL pointer dereference in the SDL stdio_read function in
file/SDL_rwops.c. (CVE-2019-12217)

An issue was discovered in libSDL2.a in Simple DirectMedia Layer (SDL)
2.0.9 when used in conjunction with libSDL2_image.a in SDL2_image 2.0.4.
There is a NULL pointer dereference in the SDL2_image function
IMG_LoadPCX_RW at IMG_pcx.c. (CVE-2019-12218)

An issue was discovered in libSDL2.a in Simple DirectMedia Layer (SDL)
2.0.9 when used in conjunction with libSDL2_image.a in SDL2_image 2.0.4.
There is an invalid free error in the SDL function SDL_SetError_REAL at
SDL_error.c. (CVE-2019-12219)

An issue was discovered in libSDL2.a in Simple DirectMedia Layer (SDL)
2.0.9 when used in conjunction with libSDL2_image.a in SDL2_image 2.0.4.
There is an out-of-bounds read in the SDL function SDL_FreePalette_REAL
at video/SDL_pixels.c. (CVE-2019-12220)

An issue was discovered in libSDL2.a in Simple ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'sdl2_image' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2_image-devel", rpm:"lib64sdl2_image-devel~2.0.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2_image-static-devel", rpm:"lib64sdl2_image-static-devel~2.0.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2_image2.0_0", rpm:"lib64sdl2_image2.0_0~2.0.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2_image2.0_0-test", rpm:"lib64sdl2_image2.0_0-test~2.0.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2_image-devel", rpm:"libsdl2_image-devel~2.0.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2_image-static-devel", rpm:"libsdl2_image-static-devel~2.0.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2_image2.0_0", rpm:"libsdl2_image2.0_0~2.0.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2_image2.0_0-test", rpm:"libsdl2_image2.0_0-test~2.0.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sdl2_image", rpm:"sdl2_image~2.0.5~1.mga7", rls:"MAGEIA7"))) {
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
