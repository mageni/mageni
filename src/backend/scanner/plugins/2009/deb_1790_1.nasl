# OpenVAS Vulnerability Test
# $Id: deb_1790_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1790-1 (xpdf)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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

include("revisions-lib.inc");
tag_insight = "Several vulnerabilities have been identified in xpdf, a suite of tools
for viewing and converting Portable Document Format (PDF) files.

For details on the issues addressed with this update, please visit
the referenced security advisories.

For the old stable distribution (etch), these problems have been fixed in version
3.01-9.1+etch6.

For the stable distribution (lenny), these problems have been fixed in version
3.02-1.4+lenny1.

For the unstable distribution (sid), these problems will be fixed in a
forthcoming version.

We recommend that you upgrade your xpdf packages.";
tag_summary = "The remote host is missing an update to xpdf
announced via advisory DSA 1790-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201790-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309861");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-05-11 20:24:31 +0200 (Mon, 11 May 2009)");
 script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1790-1 (xpdf)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"xpdf-common", ver:"3.02-1.4+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xpdf", ver:"3.02-1.4+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xpdf-reader", ver:"3.02-1.4+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xpdf-utils", ver:"3.02-1.4+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

# The xpdf package of Debian 6.0 has the same version as in 5.0.
# It is not vulnerable, but we need to run the check to have __pkg_match
# be set so that we can report a proper "not vulnerable".
if (report == "") {
  res = isdpkgvuln(pkg:"xpdf-common", ver:"3.02-1.4", rls:"DEB6.0");
  res = isdpkgvuln(pkg:"xpdf", ver:"3.02-1.4", rls:"DEB6.0");
  res = isdpkgvuln(pkg:"xpdf-reader", ver:"3.02-1.4", rls:"DEB6.0");
  res = isdpkgvuln(pkg:"xpdf-utils", ver:"3.02-1.4", rls:"DEB6.0");
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
