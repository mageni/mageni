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
  script_oid("1.3.6.1.4.1.25623.1.0.893036");
  script_version("2022-06-09T14:06:34+0000");
  script_cve_id("CVE-2022-24763", "CVE-2022-24792", "CVE-2022-24793");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-06-10 10:05:32 +0000 (Fri, 10 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 15:22:00 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-06-01 13:28:16 +0000 (Wed, 01 Jun 2022)");
  script_name("Debian LTS: Security Advisory for pjproject (DLA-3036-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/05/msg00047.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3036-1");
  script_xref(name:"Advisory-ID", value:"DLA-3036-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pjproject'
  package(s) announced via the DLA-3036-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in pjproject, is a free and 
open source multimedia communication library 

CVE-2022-24763

a denial-of-service vulnerability that affects PJSIP users that 
consume PJSIP's XML parsing in their apps.

CVE-2022-24792

A denial-of-service vulnerability affects applications on a 32-bit 
systems to play/read invalid WAV files. The vulnerability occurs 
when reading WAV file data chunks with length greater than 31-bit 
integers. The vulnerability does not affect 64-bit apps and should 
not affect apps that only plays trusted WAV files

CVE-2022-24793

A buffer overflow vulnerability affects applications that uses 
PJSIP DNS resolution. It doesn't affect PJSIP users who utilize an 
external resolver.");

  script_tag(name:"affected", value:"'pjproject' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2.5.5~dfsg-6+deb9u5.

We recommend that you upgrade your pjproject packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libpj2", ver:"2.5.5~dfsg-6+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjlib-util2", ver:"2.5.5~dfsg-6+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjmedia-audiodev2", ver:"2.5.5~dfsg-6+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjmedia-codec2", ver:"2.5.5~dfsg-6+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjmedia-videodev2", ver:"2.5.5~dfsg-6+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjmedia2", ver:"2.5.5~dfsg-6+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjnath2", ver:"2.5.5~dfsg-6+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjproject-dev", ver:"2.5.5~dfsg-6+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjsip-simple2", ver:"2.5.5~dfsg-6+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjsip-ua2", ver:"2.5.5~dfsg-6+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjsip2", ver:"2.5.5~dfsg-6+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjsua2", ver:"2.5.5~dfsg-6+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpjsua2-2v5", ver:"2.5.5~dfsg-6+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-pjproject", ver:"2.5.5~dfsg-6+deb9u5", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
