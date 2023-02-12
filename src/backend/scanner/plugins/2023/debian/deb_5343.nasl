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
  script_oid("1.3.6.1.4.1.25623.1.0.705343");
  script_version("2023-02-10T08:43:29+0000");
  script_cve_id("CVE-2022-2097", "CVE-2022-4304", "CVE-2022-4450", "CVE-2023-0215", "CVE-2023-0286");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-02-10 08:43:29 +0000 (Fri, 10 Feb 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-26 18:03:00 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"creation_date", value:"2023-02-09 02:00:15 +0000 (Thu, 09 Feb 2023)");
  script_name("Debian: Security Advisory for openssl (DSA-5343-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5343.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5343-1");
  script_xref(name:"Advisory-ID", value:"DSA-5343-1");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20220705.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20230207.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the DSA-5343-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in OpenSSL, a Secure
Sockets Layer toolkit, which may result in incomplete encryption, side
channel attacks, denial of service or information disclosure.

Additional details can be found in the upstream advisories at
[link moved to references] and
[link moved to references]");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), these problems have been fixed in
version 1.1.1n-0+deb11u4.

We recommend that you upgrade your openssl packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libcrypto1.1-udeb", ver:"1.1.1n-0+deb11u4", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libssl-dev", ver:"1.1.1n-0+deb11u4", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libssl-doc", ver:"1.1.1n-0+deb11u4", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libssl1.1", ver:"1.1.1n-0+deb11u4", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libssl1.1-udeb", ver:"1.1.1n-0+deb11u4", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.1.1n-0+deb11u4", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
