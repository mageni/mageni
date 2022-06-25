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
  script_oid("1.3.6.1.4.1.25623.1.0.892636");
  script_version("2021-04-24T03:02:41+0000");
  script_cve_id("CVE-2021-21375");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-04-26 10:09:32 +0000 (Mon, 26 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-24 03:02:41 +0000 (Sat, 24 Apr 2021)");
  script_name("Debian LTS: Security Advisory for pjproject (DLA-2636-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00023.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2636-1");
  script_xref(name:"Advisory-ID", value:"DLA-2636-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pjproject'
  package(s) announced via the DLA-2636-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue has been found in pjproject, a set of libraries for the PJ
Project.
Due to bad handling of two consecutive crafted answers to an INVITE, the
attacker is able to crash the server resulting in a denial of service.");

  script_tag(name:"affected", value:"'pjproject' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
2.5.5~dfsg-6+deb9u2.

We recommend that you upgrade your pjproject packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libpj2", ver:"2.5.5~dfsg-6+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjlib-util2", ver:"2.5.5~dfsg-6+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjmedia-audiodev2", ver:"2.5.5~dfsg-6+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjmedia-codec2", ver:"2.5.5~dfsg-6+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjmedia-videodev2", ver:"2.5.5~dfsg-6+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjmedia2", ver:"2.5.5~dfsg-6+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjnath2", ver:"2.5.5~dfsg-6+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjproject-dev", ver:"2.5.5~dfsg-6+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjsip-simple2", ver:"2.5.5~dfsg-6+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjsip-ua2", ver:"2.5.5~dfsg-6+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjsip2", ver:"2.5.5~dfsg-6+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjsua2", ver:"2.5.5~dfsg-6+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjsua2-2v5", ver:"2.5.5~dfsg-6+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-pjproject", ver:"2.5.5~dfsg-6+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
