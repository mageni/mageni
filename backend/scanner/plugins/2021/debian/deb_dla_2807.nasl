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
  script_oid("1.3.6.1.4.1.25623.1.0.892807");
  script_version("2021-11-15T09:54:42+0000");
  script_cve_id("CVE-2018-5740", "CVE-2021-25219");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2021-11-02 02:00:22 +0000 (Tue, 02 Nov 2021)");
  script_name("Debian LTS: Security Advisory for bind9 (DLA-2807-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/11/msg00001.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2807-1");
  script_xref(name:"Advisory-ID", value:"DLA-2807-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/905743");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9'
  package(s) announced via the DLA-2807-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-25219

Kishore Kumar Kothapalli discovered that the lame server cache in BIND,
a DNS server implementation, can be abused by an attacker to
significantly degrade resolver performance, resulting in denial of
service (large delays for responses for client queries and DNS timeouts
on client hosts).

CVE-2018-5740

'deny-answer-aliases' is a little-used feature intended to help recursive
server operators protect end users against DNS rebinding attacks, a
potential method of circumventing the security model used by client
browsers. However, a defect in this feature makes it easy, when the
feature is in use, to experience an assertion failure in name.c.");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1:9.10.3.dfsg.P4-12.3+deb9u10.

We recommend that you upgrade your bind9 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bind9-doc", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bind9-host", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bind9utils", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dnsutils", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"host", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbind-dev", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbind-export-dev", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbind9-140", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libdns-export162", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libdns162", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libirs-export141", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libirs141", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisc-export160", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisc160", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccc-export140", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccc140", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccfg-export140", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libisccfg140", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblwres141", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lwresd", ver:"1:9.10.3.dfsg.P4-12.3+deb9u10", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
