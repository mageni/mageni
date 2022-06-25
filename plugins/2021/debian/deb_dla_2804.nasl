# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892804");
  script_version("2021-11-15T09:54:42+0000");
  script_cve_id("CVE-2019-13616", "CVE-2019-7572", "CVE-2019-7573", "CVE-2019-7574", "CVE-2019-7575", "CVE-2019-7576", "CVE-2019-7577", "CVE-2019-7578", "CVE-2019-7635", "CVE-2019-7636", "CVE-2019-7637", "CVE-2019-7638");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-10 03:15:00 +0000 (Tue, 10 Sep 2019)");
  script_tag(name:"creation_date", value:"2021-11-01 02:00:24 +0000 (Mon, 01 Nov 2021)");
  script_name("Debian LTS: Security Advisory for libsdl1.2 (DLA-2804-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/10/msg00032.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2804-1");
  script_xref(name:"Advisory-ID", value:"DLA-2804-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/924609");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsdl1.2'
  package(s) announced via the DLA-2804-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerability have been fixed in libsdl2, the older version of
the Simple DirectMedia Layer library that provides low level access to
audio, keyboard, mouse, joystick, and graphics hardware.

CVE-2019-7572

Buffer over-read in IMA_ADPCM_nibble in audio/SDL_wave.c

CVE-2019-7573

Heap-based buffer over-read in InitMS_ADPCM in audio/SDL_wave.c

CVE-2019-7574

Heap-based buffer over-read in IMA_ADPCM_decode in audio/SDL_wave.c

CVE-2019-7575

Heap-based buffer overflow in MS_ADPCM_decode in audio/SDL_wave.c

CVE-2019-7576

Heap-based buffer over-read in InitMS_ADPCM in audio/SDL_wave.c

CVE-2019-7577

Buffer over-read in SDL_LoadWAV_RW in audio/SDL_wave.c

CVE-2019-7578

Heap-based buffer over-read in InitIMA_ADPCM in audio/SDL_wave.c

CVE-2019-7635

Heap-based buffer over-read in Blit1to4 in video/SDL_blit_1.c

CVE-2019-7636

Heap-based buffer over-read in SDL_GetRGB in video/SDL_pixels.c

CVE-2019-7637

Heap-based buffer overflow in SDL_FillRect in video/SDL_surface.c

CVE-2019-7638

Heap-based buffer over-read in Map1toN in video/SDL_pixels.c

CVE-2019-13616

Heap-based buffer over-read in BlitNtoN in video/SDL_blit_N.c");

  script_tag(name:"affected", value:"'libsdl1.2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1.2.15+dfsg1-4+deb9u1.

We recommend that you upgrade your libsdl1.2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libsdl1.2-dev", ver:"1.2.15+dfsg1-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsdl1.2debian", ver:"1.2.15+dfsg1-4+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
