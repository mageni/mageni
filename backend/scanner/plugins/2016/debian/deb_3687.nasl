# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 3687-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703687");
  script_version("2021-11-23T15:20:34+0000");
  script_cve_id("CVE-2016-1951");
  script_name("Debian Security Advisory DSA 3687-1 (nspr - security update)");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2016-10-05 00:00:00 +0200 (Wed, 05 Oct 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:02:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3687.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"nspr on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie),
these problems have been fixed in version 2:4.12-1+debu8u1.

For the unstable distribution (sid), these problems have been fixed in
version 2:4.12-1.

We recommend that you upgrade your nspr packages.");
  script_tag(name:"summary", value:"Two vulnerabilities were reported
in NSPR, a library to abstract over operating system interfaces developed
by the Mozilla project.

CVE-2016-1951
q1 reported that the NSPR implementation of sprintf-style string
formatting function miscomputed memory allocation sizes,
potentially leading to heap-based buffer overflows

The second issue concerns environment variable processing in NSPR.
The library did not ignore environment variables used to configuring
logging and tracing in processes which underwent a SUID/SGID/AT_SECURE
transition at process start. In certain system configurations, this
allowed local users to escalate their privileges.

In addition, this nspr update contains further stability and
correctness fixes and contains support code for an upcoming nss
update.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libnspr4:amd64", ver:"2:4.12-1+debu8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnspr4:i386", ver:"2:4.12-1+debu8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libnspr4-0d:amd64", ver:"2:4.12-1+debu8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnspr4-0d:i386", ver:"2:4.12-1+debu8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libnspr4-dbg:amd64", ver:"2:4.12-1+debu8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnspr4-dbg:i386", ver:"2:4.12-1+debu8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libnspr4-dev", ver:"2:4.12-1+debu8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}