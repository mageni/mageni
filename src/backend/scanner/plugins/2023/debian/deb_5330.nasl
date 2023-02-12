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
  script_oid("1.3.6.1.4.1.25623.1.0.705330");
  script_version("2023-01-30T10:09:19+0000");
  script_cve_id("CVE-2022-27774", "CVE-2022-32221", "CVE-2022-43552");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-30 10:09:19 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-14 18:11:00 +0000 (Tue, 14 Jun 2022)");
  script_tag(name:"creation_date", value:"2023-01-30 02:00:38 +0000 (Mon, 30 Jan 2023)");
  script_name("Debian: Security Advisory for curl (DSA-5330-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5330.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5330-1");
  script_xref(name:"Advisory-ID", value:"DSA-5330-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl'
  package(s) announced via the DSA-5330-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in Curl, an easy-to-use client-side
URL transfer library, which could result in denial of service or
information disclosure.");

  script_tag(name:"affected", value:"'curl' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), these problems have been fixed in
version 7.74.0-1.3+deb11u5. This update also revises the fix for CVE-2022-27774 released in DSA-5197-1.

We recommend that you upgrade your curl packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"7.74.0-1.3+deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.74.0-1.3+deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.74.0-1.3+deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4", ver:"7.74.0-1.3+deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-doc", ver:"7.74.0-1.3+deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.74.0-1.3+deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-nss-dev", ver:"7.74.0-1.3+deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.74.0-1.3+deb11u5", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
