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
  script_oid("1.3.6.1.4.1.25623.1.0.892278");
  script_version("2020-07-17T12:33:38+0000");
  script_cve_id("CVE-2018-19132", "CVE-2019-12519", "CVE-2019-12520", "CVE-2019-12521", "CVE-2019-12523", "CVE-2019-12524", "CVE-2019-12525", "CVE-2019-12526", "CVE-2019-12528", "CVE-2019-12529", "CVE-2019-13345", "CVE-2019-18676", "CVE-2019-18677", "CVE-2019-18678", "CVE-2019-18679", "CVE-2019-18860", "CVE-2020-11945", "CVE-2020-8449", "CVE-2020-8450");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-07-20 10:03:49 +0000 (Mon, 20 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-17 12:33:38 +0000 (Fri, 17 Jul 2020)");
  script_name("Debian LTS: Security Advisory for squid3 (DLA-2278-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00009.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2278-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/950802");
  script_xref(name:"URL", value:"https://bugs.debian.org/931478");
  script_xref(name:"URL", value:"https://bugs.debian.org/950925");
  script_xref(name:"URL", value:"https://bugs.debian.org/912294");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid3'
  package(s) announced via the DLA-2278-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that Squid, a high-performance proxy caching server for
web clients, has been affected by multiple security vulnerabilities.
Due to incorrect input validation and URL request handling it was
possible to bypass access restrictions for restricted HTTP servers
and to cause a denial-of-service.");

  script_tag(name:"affected", value:"'squid3' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
3.5.23-5+deb9u2.

We recommend that you upgrade your squid3 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"3.5.23-5+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-cgi", ver:"3.5.23-5+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-common", ver:"3.5.23-5+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-dbg", ver:"3.5.23-5+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-purge", ver:"3.5.23-5+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid3", ver:"3.5.23-5+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squidclient", ver:"3.5.23-5+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
