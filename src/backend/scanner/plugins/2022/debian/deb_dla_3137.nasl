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
  script_oid("1.3.6.1.4.1.25623.1.0.893137");
  script_version("2022-10-10T10:12:14+0000");
  script_cve_id("CVE-2021-22930", "CVE-2021-22939", "CVE-2021-22940", "CVE-2022-21824", "CVE-2022-32212");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-10-10 10:12:14 +0000 (Mon, 10 Oct 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-18 17:15:00 +0000 (Mon, 18 Oct 2021)");
  script_tag(name:"creation_date", value:"2022-10-06 01:00:14 +0000 (Thu, 06 Oct 2022)");
  script_name("Debian LTS: Security Advisory for nodejs (DLA-3137-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/10/msg00006.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3137-1");
  script_xref(name:"Advisory-ID", value:"DLA-3137-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1004177");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs'
  package(s) announced via the DLA-3137-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in Node.js, a JavaScript
runtime environment, which could result in memory corruption, invalid
certificate validation, prototype pollution or command injection.

CVE-2021-22930, CVE-2021-22940

Use after free attack where an attacker might be able to exploit
the memory corruption, to change process behavior.

CVE-2021-22939

If the Node.js https API was used incorrectly and 'undefined' was
in passed for the 'rejectUnauthorized' parameter, no error was
returned and connections to servers with an expired certificate
would have been accepted.

CVE-2022-21824

Due to the formatting logic of the 'console.table()' function it
was not safe to allow user controlled input to be passed to the
'properties' parameter while simultaneously passing a plain object
with at least one property as the first parameter, which could be
'__proto__'.

CVE-2022-32212

OS Command Injection vulnerability due to an insufficient
IsAllowedHost check that can easily be bypassed because
IsIPAddress does not properly check if an IP address is invalid
before making DBS requests allowing rebinding attacks.");

  script_tag(name:"affected", value:"'nodejs' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
10.24.0~dfsg-1~deb10u2.

We recommend that you upgrade your nodejs packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libnode-dev", ver:"10.24.0~dfsg-1~deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnode64", ver:"10.24.0~dfsg-1~deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"10.24.0~dfsg-1~deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nodejs-doc", ver:"10.24.0~dfsg-1~deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
