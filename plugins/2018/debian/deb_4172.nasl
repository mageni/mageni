###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4172.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DSA 4172-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704172");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2018-6797", "CVE-2018-6798", "CVE-2018-6913");
  script_name("Debian Security Advisory DSA 4172-1 (perl - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-04-14 00:00:00 +0200 (Sat, 14 Apr 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4172.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB[89]");
  script_tag(name:"affected", value:"perl on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 5.20.2-3+deb8u10. The oldstable distribution (jessie) update
contains only a fix for CVE-2018-6913 .

For the stable distribution (stretch), these problems have been fixed in
version 5.24.1-3+deb9u3.

We recommend that you upgrade your perl packages.

For the detailed security status of perl please refer to its security
tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/perl");
  script_tag(name:"summary", value:"Multiple vulnerabilities were discovered in the implementation of the
Perl programming language. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2018-6797
Brian Carpenter reported that a crafted regular expression
could cause a heap buffer write overflow, with control over the
bytes written.

CVE-2018-6798
Nguyen Duc Manh reported that matching a crafted locale dependent
regular expression could cause a heap buffer read overflow and
potentially information disclosure.

CVE-2018-6913
GwanYeong Kim reported that 'pack()' could cause a heap buffer write
overflow with a large item count.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libperl-dev", ver:"5.20.2-3+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libperl5.20", ver:"5.20.2-3+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl", ver:"5.20.2-3+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-base", ver:"5.20.2-3+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-debug", ver:"5.20.2-3+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-doc", ver:"5.20.2-3+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-modules", ver:"5.20.2-3+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libperl-dev", ver:"5.24.1-3+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libperl5.24", ver:"5.24.1-3+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl", ver:"5.24.1-3+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-base", ver:"5.24.1-3+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-debug", ver:"5.24.1-3+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-doc", ver:"5.24.1-3+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-modules-5.24", ver:"5.24.1-3+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}