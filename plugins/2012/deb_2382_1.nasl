# OpenVAS Vulnerability Test
# $Id: deb_2382_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2382-1 (ecryptfs-utils)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.70701");
  script_cve_id("CVE-2011-1831", "CVE-2011-1832", "CVE-2011-1834",
               "CVE-2011-1835", "CVE-2011-1837", "CVE-2011-3145");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-11 03:26:49 -0500 (Sat, 11 Feb 2012)");
  script_name("Debian Security Advisory DSA 2382-1 (ecryptfs-utils)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6|7)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202382-1");
  script_tag(name:"insight", value:"Several problems have been discovered in ecryptfs-utils, a cryptographic
filesystem for Linux.

CVE-2011-1831

Vasiliy Kulikov of Openwall and Dan Rosenberg discovered that eCryptfs
incorrectly validated permissions on the requested mountpoint. A local
attacker could use this flaw to mount to arbitrary locations, leading
to privilege escalation.

CVE-2011-1832

Vasiliy Kulikov of Openwall and Dan Rosenberg discovered that eCryptfs
incorrectly validated permissions on the requested mountpoint. A local
attacker could use this flaw to unmount to arbitrary locations, leading
to a denial of service.

CVE-2011-1834

Dan Rosenberg and Marc Deslauriers discovered that eCryptfs incorrectly
handled modifications to the mtab file when an error occurs. A local
attacker could use this flaw to corrupt the mtab file, and possibly
unmount arbitrary locations, leading to a denial of service.

CVE-2011-1835

Marc Deslauriers discovered that eCryptfs incorrectly handled keys when
setting up an encrypted private directory. A local attacker could use
this flaw to manipulate keys during creation of a new user.

CVE-2011-1837

Vasiliy Kulikov of Openwall discovered that eCryptfs incorrectly handled
lock counters. A local attacker could use this flaw to possibly overwrite
arbitrary files.

We acknowledge the work of the Ubuntu distribution in preparing patches
suitable for near-direct inclusion in the Debian package.

For the oldstable distribution (lenny), these problems have been fixed in
version 68-1+lenny1.

For the stable distribution (squeeze), these problems have been fixed in
version 83-4+squeeze1.

For the testing distribution (wheezy) and the unstable distribution (sid),
these problems have been fixed in version 95-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your ecryptfs-utils packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to ecryptfs-utils
announced via advisory DSA 2382-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"ecryptfs-utils", ver:"68-1+lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libecryptfs-dev", ver:"68-1+lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libecryptfs0", ver:"68-1+lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ecryptfs-utils", ver:"83-4+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ecryptfs-utils-dbg", ver:"83-4+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libecryptfs-dev", ver:"83-4+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libecryptfs0", ver:"83-4+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ecryptfs-utils", ver:"95-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ecryptfs-utils-dbg", ver:"95-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libecryptfs-dev", ver:"95-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libecryptfs0", ver:"95-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-ecryptfs", ver:"95-1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}