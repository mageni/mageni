# OpenVAS Vulnerability Test
# $Id: deb_2224_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2224-1 (openjdk-6)
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
  script_oid("1.3.6.1.4.1.25623.1.0.69567");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4351", "CVE-2010-4448", "CVE-2010-4450", "CVE-2010-4465", "CVE-2010-4469", "CVE-2010-4470", "CVE-2010-4471", "CVE-2010-4472", "CVE-2011-0025", "CVE-2011-0706");
  script_name("Debian Security Advisory DSA 2224-1 (openjdk-6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6|7)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202224-1");
  script_tag(name:"insight", value:"Several security vulnerabilities were discovered in OpenJDK, an
implementation of the Java platform.

CVE-2010-4351
The JNLP SecurityManager returns from the checkPermission method
instead of throwing an exception in certain circumstances, which
might allow context-dependent attackers to bypass the intended
security policy by creating instances of ClassLoader.

CVE-2010-4448
Malicious applets can perform DNS cache poisoning.

CVE-2010-4450
An empty (but set) LD_LIBRARY_PATH environment variable results in
a misconstructed library search path, resulting in code execution
from possibly untrusted sources.

CVE-2010-4465
Malicious applets can extend their privileges by abusing Swing
timers.

CVE-2010-4469
The Hotspot just-in-time compiler miscompiles crafted byte
sequences, resulting in heap corruption.

CVE-2010-4470
JAXP can be exploited by untrusted code to elevate privileges.

CVE-2010-4471
Java2D can be exploited by untrusted code to elevate privileges.

CVE-2010-4472
Untrusted code can replace the XML DSIG implementation.

CVE-2011-0025
Signatures on JAR files are not properly verified, which allows
remote attackers to trick users into executing code that appears
to come from a trusted source.

CVE-2011-0706
The JNLPClassLoader class allows remote attackers to gain
privileges via unknown vectors related to multiple signers and the
assignment of an inappropriate security descriptor

In addition, this security update contains stability fixes, such as
switching to the recommended Hotspot version (hs14) for this
particular version of OpenJDK.

For the oldstable distribution (lenny), these problems have been fixed in
version 6b18-1.8.7-2~lenny1.

For the stable distribution (squeeze), these problems have been fixed in
version 6b18-1.8.7-2~squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems have been fixed in version 1.8.7-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your openjdk-6 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to openjdk-6
announced via advisory DSA 2224-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"openjdk-6-dbg", ver:"6b18-1.8.7-2~lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b18-1.8.7-2~lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b18-1.8.7-2~lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b18-1.8.7-2~lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b18-1.8.7-2~lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b18-1.8.7-2~lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b18-1.8.7-2~lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-source", ver:"6b18-1.8.7-2~lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b18-1.8.7-2~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b18-1.8.7-2~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-dbg", ver:"6b18-1.8.7-2~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b18-1.8.7-2~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b18-1.8.7-2~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b18-1.8.7-2~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b18-1.8.7-2~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b18-1.8.7-2~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b18-1.8.7-2~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b18-1.8.7-2~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-source", ver:"6b18-1.8.7-2~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"1.8.7-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"1.8.7-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-dbg", ver:"1.8.7-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"1.8.7-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"1.8.7-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"1.8.7-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"1.8.7-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"1.8.7-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"1.8.7-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"1.8.7-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-source", ver:"1.8.7-1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}