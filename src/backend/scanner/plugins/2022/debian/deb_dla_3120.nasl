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
  script_oid("1.3.6.1.4.1.25623.1.0.893120");
  script_version("2022-09-27T10:12:08+0000");
  script_cve_id("CVE-2018-18897", "CVE-2018-19058", "CVE-2018-20650", "CVE-2019-14494", "CVE-2019-9903", "CVE-2019-9959", "CVE-2020-27778", "CVE-2022-27337", "CVE-2022-38784");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-09-27 10:12:08 +0000 (Tue, 27 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-07 19:30:00 +0000 (Mon, 07 Dec 2020)");
  script_tag(name:"creation_date", value:"2022-09-26 01:00:15 +0000 (Mon, 26 Sep 2022)");
  script_name("Debian LTS: Security Advisory for poppler (DLA-3120-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/09/msg00030.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3120-1");
  script_xref(name:"Advisory-ID", value:"DLA-3120-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/913164");
  script_xref(name:"URL", value:"https://bugs.debian.org/913177");
  script_xref(name:"URL", value:"https://bugs.debian.org/917974");
  script_xref(name:"URL", value:"https://bugs.debian.org/925264");
  script_xref(name:"URL", value:"https://bugs.debian.org/941776");
  script_xref(name:"URL", value:"https://bugs.debian.org/933812");
  script_xref(name:"URL", value:"https://bugs.debian.org/1010695");
  script_xref(name:"URL", value:"https://bugs.debian.org/1018971");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler'
  package(s) announced via the DLA-3120-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in Poppler, a PDF
rendering library, that could lead to denial of service or possibly other
unspecified impact when processing maliciously crafted documents.");

  script_tag(name:"affected", value:"'poppler' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
0.71.0-5+deb10u1.

We recommend that you upgrade your poppler packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-poppler-0.18", ver:"0.71.0-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-cpp-dev", ver:"0.71.0-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-cpp0v5", ver:"0.71.0-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-dev", ver:"0.71.0-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib-dev", ver:"0.71.0-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib-doc", ver:"0.71.0-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib8", ver:"0.71.0-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-private-dev", ver:"0.71.0-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt5-1", ver:"0.71.0-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt5-dev", ver:"0.71.0-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler82", ver:"0.71.0-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"poppler-utils", ver:"0.71.0-5+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
