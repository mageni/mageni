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
  script_oid("1.3.6.1.4.1.25623.1.0.704694");
  script_version("2020-05-28T03:00:07+0000");
  script_cve_id("CVE-2020-12662", "CVE-2020-12663");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-05-28 03:00:07 +0000 (Thu, 28 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-28 03:00:07 +0000 (Thu, 28 May 2020)");
  script_name("Debian: Security Advisory for unbound (DSA-4694-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4694.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4694-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unbound'
  package(s) announced via the DSA-4694-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabiliites have been discovered in Unbound, a recursive-only
caching DNS server, a traffic amplification attack against third party
authoritative name servers (NXNSAttack) and insufficient sanitisation
of replies from upstream servers could result in denial of service via
an infinite loop.

The version of Unbound in the oldstable distribution (stretch) is
no longer supported. If these security issues affect your setup, you
should upgrade to the stable distribution (buster).");

  script_tag(name:"affected", value:"'unbound' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 1.9.0-2+deb10u2.

We recommend that you upgrade your unbound packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libunbound-dev", ver:"1.9.0-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libunbound8", ver:"1.9.0-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-unbound", ver:"1.9.0-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-unbound", ver:"1.9.0-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"unbound", ver:"1.9.0-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"unbound-anchor", ver:"1.9.0-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"unbound-host", ver:"1.9.0-2+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
