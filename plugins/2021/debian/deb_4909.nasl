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
  script_oid("1.3.6.1.4.1.25623.1.0.704909");
  script_version("2021-05-02T03:00:09+0000");
  script_cve_id("CVE-2021-25214", "CVE-2021-25215", "CVE-2021-25216");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-05-03 10:25:12 +0000 (Mon, 03 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-02 03:00:09 +0000 (Sun, 02 May 2021)");
  script_name("Debian: Security Advisory for bind9 (DSA-4909-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4909.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4909-1");
  script_xref(name:"Advisory-ID", value:"DSA-4909-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9'
  package(s) announced via the DSA-4909-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in BIND, a DNS server
implementation.

CVE-2021-25214
Greg Kuechle discovered that a malformed incoming IXFR transfer
could trigger an assertion failure in named, resulting in denial
of service.

CVE-2021-25215
Siva Kakarla discovered that named could crash when a DNAME record
placed in the ANSWER section during DNAME chasing turned out to be
the final answer to a client query.

CVE-2021-25216
It was discovered that the SPNEGO implementation used by BIND is
prone to a buffer overflow vulnerability. This update switches to
use the SPNEGO implementation from the Kerberos libraries.");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 1:9.11.5.P4+dfsg-5.1+deb10u5.

We recommend that you upgrade your bind9 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bind9-doc", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bind9-host", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bind9utils", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dnsutils", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbind-dev", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbind-export-dev", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbind9-161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libdns-export1104", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libdns1104", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libirs-export161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libirs161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisc-export1100", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisc1100", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccc-export161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccc161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccfg-export163", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccfg163", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblwres161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
