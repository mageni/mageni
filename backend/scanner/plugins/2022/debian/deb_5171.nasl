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
  script_oid("1.3.6.1.4.1.25623.1.0.705171");
  script_version("2022-06-30T09:43:30+0000");
  script_cve_id("CVE-2021-28116", "CVE-2021-46784");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-06-30 09:43:30 +0000 (Thu, 30 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-11 03:15:00 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"creation_date", value:"2022-06-29 01:00:06 +0000 (Wed, 29 Jun 2022)");
  script_name("Debian: Security Advisory for squid (DSA-5171-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|10)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5171.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5171-1");
  script_xref(name:"Advisory-ID", value:"DSA-5171-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid'
  package(s) announced via the DSA-5171-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in the Squid proxy caching
server:

CVE-2021-28116
Amos Jeffries discovered an information leak if WCCPv2 is enabled

CVE-2021-46784
Joshua Rogers discovered that an error in parsing Gopher server
responses may result in denial of service");

  script_tag(name:"affected", value:"'squid' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (buster), these problems have been fixed
in version 4.6-1+deb10u7.

For the stable distribution (bullseye), these problems have been fixed in
version 4.13-10+deb11u1.

We recommend that you upgrade your squid packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"4.13-10+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-cgi", ver:"4.13-10+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-common", ver:"4.13-10+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-openssl", ver:"4.13-10+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-purge", ver:"4.13-10+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squidclient", ver:"4.13-10+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"4.6-1+deb10u7", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-cgi", ver:"4.6-1+deb10u7", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-common", ver:"4.6-1+deb10u7", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-purge", ver:"4.6-1+deb10u7", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid3", ver:"4.6-1+deb10u7", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squidclient", ver:"4.6-1+deb10u7", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
