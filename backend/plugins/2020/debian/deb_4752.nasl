# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704752");
  script_version("2020-08-28T03:00:16+0000");
  script_cve_id("CVE-2020-8619", "CVE-2020-8622", "CVE-2020-8623", "CVE-2020-8624");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-08-28 09:48:35 +0000 (Fri, 28 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-28 03:00:16 +0000 (Fri, 28 Aug 2020)");
  script_name("Debian: Security Advisory for bind9 (DSA-4752-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4752.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4752-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9'
  package(s) announced via the DSA-4752-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in BIND, a DNS server
implementation.

CVE-2020-8619
It was discovered that an asterisk character in an empty non terminal can cause an assertion failure, resulting in denial
of service.

CVE-2020-8622
Dave Feldman, Jeff Warren, and Joel Cunningham reported that a
truncated TSIG response can lead to an assertion failure, resulting
in denial of service.

CVE-2020-8623
Lyu Chiy reported that a flaw in the native PKCS#11 code can lead
to a remotely triggerable assertion failure, resulting in denial
of service.

CVE-2020-8624
Joop Boonen reported that update-policy rules of type subdomain
are enforced incorrectly, allowing updates to all parts of the zone
along with the intended subdomain.");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 1:9.11.5.P4+dfsg-5.1+deb10u2.

We recommend that you upgrade your bind9 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bind9-doc", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bind9-host", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bind9utils", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dnsutils", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbind-dev", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbind-export-dev", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbind9-161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libdns-export1104", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libdns1104", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libirs-export161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libirs161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisc-export1100", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisc1100", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccc-export161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccc161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccfg-export163", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccfg163", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblwres161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
