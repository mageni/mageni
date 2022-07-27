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
  script_oid("1.3.6.1.4.1.25623.1.0.892728");
  script_version("2021-08-04T03:00:11+0000");
  script_cve_id("CVE-2021-25801", "CVE-2021-25802", "CVE-2021-25803", "CVE-2021-25804");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-08-04 10:51:24 +0000 (Wed, 04 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-04 03:00:11 +0000 (Wed, 04 Aug 2021)");
  script_name("Debian LTS: Security Advisory for vlc (DLA-2728-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/08/msg00004.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2728-1");
  script_xref(name:"Advisory-ID", value:"DLA-2728-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vlc'
  package(s) announced via the DLA-2728-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were a number of issues in VideoLAN (aka
'vlc', a popular video and multimedia player:

  - CVE-2021-25801: A buffer overflow vulnerability in the __Parse_indx
component allowed attackers to cause an out-of-bounds read via a
crafted .avi file.

  - CVE-2021-25802: A buffer overflow vulnerability in the
AVI_ExtractSubtitle component could have allowed attackers to cause
an out-of-bounds read via a crafted .avi file.

  - CVE-2021-25803: A buffer overflow vulnerability in the
vlc_input_attachment_New component allowed attackers to cause an
out-of-bounds read via a specially-crafted .avi file.

  - CVE-2021-25804: A NULL-pointer dereference in 'Open' in avi.c can
result in a denial of service (DoS) vulnerability.");

  script_tag(name:"affected", value:"'vlc' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 'Stretch', these problems have been fixed in version
3.0.11-0+deb9u2.

We recommend that you upgrade your vlc packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libvlc-bin", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvlc-dev", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvlc5", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvlccore-dev", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvlccore8", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libvlccore9", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-bin", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-data", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-l10n", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-nox", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-access-extra", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-base", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-fluidsynth", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-jack", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-notify", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-qt", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-samba", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-sdl", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-skins2", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-svg", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-video-output", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-video-splitter", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-visualization", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-zvbi", ver:"3.0.11-0+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
