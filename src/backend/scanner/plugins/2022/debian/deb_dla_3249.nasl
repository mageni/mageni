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
  script_oid("1.3.6.1.4.1.25623.1.0.893249");
  script_version("2022-12-29T11:40:20+0000");
  script_cve_id("CVE-2019-16910", "CVE-2019-18222", "CVE-2020-10932", "CVE-2020-10941", "CVE-2020-16150", "CVE-2020-36421", "CVE-2020-36422", "CVE-2020-36423", "CVE-2020-36424", "CVE-2020-36425", "CVE-2020-36426", "CVE-2020-36475", "CVE-2020-36476", "CVE-2020-36478", "CVE-2021-24119", "CVE-2021-43666", "CVE-2021-44732", "CVE-2022-35409");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-12-29 11:40:20 +0000 (Thu, 29 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-29 18:48:00 +0000 (Wed, 29 Dec 2021)");
  script_tag(name:"creation_date", value:"2022-12-26 02:00:22 +0000 (Mon, 26 Dec 2022)");
  script_name("Debian LTS: Security Advisory for mbedtls (DLA-3249-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/12/msg00036.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3249-1");
  script_xref(name:"Advisory-ID", value:"DLA-3249-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/941265");
  script_xref(name:"URL", value:"https://bugs.debian.org/963159");
  script_xref(name:"URL", value:"https://bugs.debian.org/972806");
  script_xref(name:"URL", value:"https://bugs.debian.org/1002631");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mbedtls'
  package(s) announced via the DLA-3249-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been discovered in mbedtls, a
lightweight crypto and SSL/TLS library, which may allow attackers to obtain
sensitive information like the RSA private key or cause a denial of service
(application or server crash).");

  script_tag(name:"affected", value:"'mbedtls' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
2.16.9-0~deb10u1.

We recommend that you upgrade your mbedtls packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libmbedcrypto3", ver:"2.16.9-0~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmbedtls-dev", ver:"2.16.9-0~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmbedtls-doc", ver:"2.16.9-0~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmbedtls12", ver:"2.16.9-0~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmbedx509-0", ver:"2.16.9-0~deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
