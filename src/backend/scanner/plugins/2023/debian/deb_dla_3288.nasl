# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.893288");
  script_version("2023-01-31T10:08:41+0000");
  script_cve_id("CVE-2022-27774", "CVE-2022-27782", "CVE-2022-32221", "CVE-2022-35252", "CVE-2022-43552");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-10 18:33:00 +0000 (Fri, 10 Jun 2022)");
  script_tag(name:"creation_date", value:"2023-01-30 09:58:59 +0000 (Mon, 30 Jan 2023)");
  script_name("Debian LTS: Security Advisory for curl (DLA-3288-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00028.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3288-1");
  script_xref(name:"Advisory-ID", value:"DLA-3288-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl'
  package(s) announced via the DLA-3288-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Curl, an easy-to-use client-side
URL transfer library, which could result in denial of service or
information disclosure.

This update also revises the fix for CVE-2022-27782 released in DLA-3085-1.");

  script_tag(name:"affected", value:"'curl' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
7.64.0-4+deb10u4.

We recommend that you upgrade your curl packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"7.64.0-4+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.64.0-4+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.64.0-4+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4", ver:"7.64.0-4+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-doc", ver:"7.64.0-4+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.64.0-4+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-nss-dev", ver:"7.64.0-4+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.64.0-4+deb10u4", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
