# OpenVAS Vulnerability Test
# $Id: deb_2265_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2265-1 (perl)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.69971");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2011-1487");
  script_name("Debian Security Advisory DSA 2265-1 (perl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6|7)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202265-1");
  script_tag(name:"insight", value:"Mark Martinec discovered that Perl incorrectly clears the tainted flag
on values returned by case conversion functions such as lc.  This
may expose preexisting vulnerabilities in applications which use these
functions while processing untrusted input.  No such applications are
known at this stage.  Such applications will cease to work when this
security update is applied because taint checks are designed to
prevent such unsafe use of untrusted input data.

For the oldstable distribution (lenny), this problem has been fixed in
version 5.10.0-19lenny4.

For the stable distribution (squeeze), this problem has been fixed in
version 5.10.1-17squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version <missing>.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 5.10.1-20.");

  script_tag(name:"solution", value:"We recommend that you upgrade your perl packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to perl
announced via advisory DSA 2265-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libcgi-fast-perl", ver:"5.10.0-19lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libperl-dev", ver:"5.10.0-19lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libperl5.10", ver:"5.10.0-19lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl", ver:"5.10.0-19lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-base", ver:"5.10.0-19lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-debug", ver:"5.10.0-19lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-doc", ver:"5.10.0-19lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-modules", ver:"5.10.0-19lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-suid", ver:"5.10.0-19lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcgi-fast-perl", ver:"5.10.1-17squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libperl-dev", ver:"5.10.1-17squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libperl5.10", ver:"5.10.1-17squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl", ver:"5.10.1-17squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-base", ver:"5.10.1-17squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-debug", ver:"5.10.1-17squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-doc", ver:"5.10.1-17squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-modules", ver:"5.10.1-17squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-suid", ver:"5.10.1-17squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcgi-fast-perl", ver:"5.12.4-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libperl-dev", ver:"5.12.4-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libperl5.12", ver:"5.12.4-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl", ver:"5.12.4-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-base", ver:"5.12.4-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-debug", ver:"5.12.4-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-doc", ver:"5.12.4-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-modules", ver:"5.12.4-1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}