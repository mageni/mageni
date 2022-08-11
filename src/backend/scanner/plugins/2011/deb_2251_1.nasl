# OpenVAS Vulnerability Test
# $Id: deb_2251_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2251-1 (subversion)
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
  script_oid("1.3.6.1.4.1.25623.1.0.69958");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2011-1752", "CVE-2011-1783", "CVE-2011-1921");
  script_name("Debian Security Advisory DSA 2251-1 (subversion)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202251-1");
  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Subversion, the version
control system. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2011-1752

The mod_dav_svn Apache HTTPD server module can be crashed though
when asked to deliver baselined WebDAV resources.

CVE-2011-1783

The mod_dav_svn Apache HTTPD server module can trigger a loop which
consumes all available memory on the system.

CVE-2011-1921

The mod_dav_svn Apache HTTPD server module may leak to remote users
the file contents of files configured to be unreadable by those
users.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.5.1dfsg1-7.

For the stable distribution (squeeze), this problem has been fixed in
version 1.6.12dfsg-6.

For the unstable distribution (sid), this problem has been fixed in
version 1.6.17dfsg-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your subversion packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to subversion
announced via advisory DSA 2251-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.5.1dfsg1-7", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-dev", ver:"1.5.1dfsg1-7", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-doc", ver:"1.5.1dfsg1-7", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-java", ver:"1.5.1dfsg1-7", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-perl", ver:"1.5.1dfsg1-7", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-ruby", ver:"1.5.1dfsg1-7", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-ruby1.8", ver:"1.5.1dfsg1-7", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn1", ver:"1.5.1dfsg1-7", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-subversion", ver:"1.5.1dfsg1-7", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"subversion", ver:"1.5.1dfsg1-7", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"subversion-tools", ver:"1.5.1dfsg1-7", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.6.12dfsg-6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-dev", ver:"1.6.12dfsg-6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-doc", ver:"1.6.12dfsg-6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-java", ver:"1.6.12dfsg-6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-perl", ver:"1.6.12dfsg-6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-ruby", ver:"1.6.12dfsg-6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn-ruby1.8", ver:"1.6.12dfsg-6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsvn1", ver:"1.6.12dfsg-6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-subversion", ver:"1.6.12dfsg-6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"subversion", ver:"1.6.12dfsg-6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"subversion-tools", ver:"1.6.12dfsg-6", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}