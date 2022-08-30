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
  script_oid("1.3.6.1.4.1.25623.1.0.893085");
  script_version("2022-08-29T08:42:23+0000");
  script_cve_id("CVE-2021-22898", "CVE-2021-22924", "CVE-2021-22946", "CVE-2021-22947", "CVE-2022-22576", "CVE-2022-27776", "CVE-2022-27781", "CVE-2022-27782", "CVE-2022-32206", "CVE-2022-32208");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-08-29 08:42:23 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-08 13:55:00 +0000 (Wed, 08 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-08-29 01:00:15 +0000 (Mon, 29 Aug 2022)");
  script_name("Debian LTS: Security Advisory for curl (DLA-3085-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/08/msg00017.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3085-1");
  script_xref(name:"Advisory-ID", value:"DLA-3085-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/989228");
  script_xref(name:"URL", value:"https://bugs.debian.org/991492");
  script_xref(name:"URL", value:"https://bugs.debian.org/1010295");
  script_xref(name:"URL", value:"https://bugs.debian.org/1010254");
  script_xref(name:"URL", value:"https://bugs.debian.org/1010253");
  script_xref(name:"URL", value:"https://bugs.debian.org/1010252");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl'
  package(s) announced via the DLA-3085-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been discovered in cURL, an URL transfer
library. These flaws may allow remote attackers to obtain sensitive
information, leak authentication or cookie header data or facilitate a
denial of service attack.");

  script_tag(name:"affected", value:"'curl' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
7.64.0-4+deb10u3.

We recommend that you upgrade your curl packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"7.64.0-4+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.64.0-4+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.64.0-4+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4", ver:"7.64.0-4+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-doc", ver:"7.64.0-4+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.64.0-4+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-nss-dev", ver:"7.64.0-4+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.64.0-4+deb10u3", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
