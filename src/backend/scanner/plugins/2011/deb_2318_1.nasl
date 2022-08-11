# OpenVAS Vulnerability Test
# $Id: deb_2318_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2318-1 (cyrus-imapd-2.2)
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
  script_oid("1.3.6.1.4.1.25623.1.0.70407");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-10-16 23:01:53 +0200 (Sun, 16 Oct 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-3372", "CVE-2011-3208");
  script_name("Debian Security Advisory DSA 2318-1 (cyrus-imapd-2.2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202318-1");
  script_tag(name:"insight", value:"Multiple security issues have been discovered in cyrus-imapd, a highly scalable
mail system designed for use in enterprise environments.  The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2011-3208

Coverity discovered a stack-based buffer overflow in the NNTP server
implementation (nttpd) of cyrus-imapd.  An attacker can exploit this
flaw via several crafted NNTP commands to execute arbitrary code.

CVE-2011-3372

Stefan Cornelius of Secunia Research discovered that the command processing
of the NNTP server implementation (nttpd) of cyrus-imapd is not properly
implementing access restrictions for certain commands and is not checking
for a complete, successful authentication.  An attacker can use this flaw
to bypass access restrictions for some commands and, e.g. exploit
CVE-2011-3208 without proper authentication.


For the oldstable distribution (lenny), this problem has been fixed in
version 2.2_2.2.13-14+lenny5.

For the stable distribution (squeeze), this problem has been fixed in
version 2.2_2.2.13-19+squeeze2.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
cyrus-imapd-2.4 version 2.4.12-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your cyrus-imapd-2.2 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to cyrus-imapd-2.2
announced via advisory DSA 2318-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"cyrus-admin-2.2", ver:"2.2.13-14+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-clients-2.2", ver:"2.2.13-14+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-common-2.2", ver:"2.2.13-14+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-dev-2.2", ver:"2.2.13-14+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-doc-2.2", ver:"2.2.13-14+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-imapd-2.2", ver:"2.2.13-14+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-murder-2.2", ver:"2.2.13-14+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-nntpd-2.2", ver:"2.2.13-14+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-pop3d-2.2", ver:"2.2.13-14+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcyrus-imap-perl22", ver:"2.2.13-14+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-admin-2.2", ver:"2.2.13-19+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-clients-2.2", ver:"2.2.13-19+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-common-2.2", ver:"2.2.13-19+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-dev-2.2", ver:"2.2.13-19+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-doc-2.2", ver:"2.2.13-19+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-imapd-2.2", ver:"2.2.13-19+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-murder-2.2", ver:"2.2.13-19+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-nntpd-2.2", ver:"2.2.13-19+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-pop3d-2.2", ver:"2.2.13-19+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcyrus-imap-perl22", ver:"2.2.13-19+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}