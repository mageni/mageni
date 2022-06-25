# OpenVAS Vulnerability Test
# $Id: deb_2311_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2311-1 (openjdk-6)
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
  script_oid("1.3.6.1.4.1.25623.1.0.70400");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-10-16 23:01:53 +0200 (Sun, 16 Oct 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-0862", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0867", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0871");
  script_name("Debian Security Advisory DSA 2311-1 (openjdk-6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202311-1");
  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in OpenJDK, an
implementation of the Java SE platform.  The Common Vulnerabilities
and Exposures project identifies the following problems:

CVE-2011-0862
Integer overflow errors in the JPEG and font parser allow
untrusted code (including applets) to elevate its privileges.

CVE-2011-0864
Hotspot, the just-in-time compiler in OpenJDK, mishandled
certain byte code instructions, allowing untrusted code
(including applets) to crash the virtual machine.

CVE-2011-0865
A race condition in signed object deserialization could
allow untrusted code to modify signed content, apparently
leaving its signature intact.

CVE-2011-0867
Untrusted code (including applets) could access information
about network interfaces which was not intended to be public.
(Note that the interface MAC address is still available to
untrusted code.)

CVE-2011-0868
A float-to-long conversion could overflow, , allowing
untrusted code (including applets) to crash the virtual
machine.

CVE-2011-0869
Untrusted code (including applets) could intercept HTTP
requests by reconfiguring proxy settings through a SOAP
connection.

CVE-2011-0871
Untrusted code (including applets) could elevate its
privileges through the Swing MediaTracker code.

In addition, this update removes support for the Zero/Shark and Cacao
Hotspot variants from the i386 and amd64 due to stability issues.
These Hotspot variants are included in the openjdk-6-jre-zero and
icedtea-6-jre-cacao packages, and these packages must be removed
during this update.

For the oldstable distribution (lenny), these problems will be fixed
in a separate DSA for technical reasons.

For the stable distribution (squeeze), these problems have been fixed
in version 6b18-1.8.9-0.1~squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid(, these problems have been fixed in version 6b18-1.8.9-0.1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your OpenJDK packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to openjdk-6
announced via advisory DSA 2311-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b18-1.8.9-0.1~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b18-1.8.9-0.1~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-dbg", ver:"6b18-1.8.9-0.1~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b18-1.8.9-0.1~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b18-1.8.9-0.1~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b18-1.8.9-0.1~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b18-1.8.9-0.1~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b18-1.8.9-0.1~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b18-1.8.9-0.1~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b18-1.8.9-0.1~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-source", ver:"6b18-1.8.9-0.1~squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b23~pre10-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedtea-6-jre-jamvm", ver:"6b23~pre10-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-dbg", ver:"6b23~pre10-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b23~pre10-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b23~pre10-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b23~pre10-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b23~pre10-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b23~pre10-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b23~pre10-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b23~pre10-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openjdk-6-source", ver:"6b23~pre10-1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}