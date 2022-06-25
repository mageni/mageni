# OpenVAS Vulnerability Test
# $Id: deb_1684_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1684-1 (lcms)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_insight = "Two vulnerabilities have been found in lcms, a library and set of
commandline utilities for image color management.  The Common
Vulnerabilities and Exposures project identifies the following
problems:

CVE-2008-5316

Inadequate enforcement of fixed-length buffer limits allows an
attacker to overflow a buffer on the stack, potentially enabling
the execution of arbitrary code when a maliciously-crafted
image is opened.

CVS-2008-5317

An integer sign error in reading image gamma data could allow an
attacker to cause an under-sized buffer to be allocated for
subsequent image data, with unknown consequences potentially
including the execution of arbitrary code if a maliciously-crafted
image is opened.

For the stable distribution (etch), these problems have been fixed in
version 1.14-1.1+etch1.

For the upcoming stable distribution (lenny), and the unstable
distribution (sid), these problems are fixed in version 1.17.dfsg-1.

We recommend that you upgrade your lcms packages.";
tag_summary = "The remote host is missing an update to lcms
announced via advisory DSA 1684-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201684-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301351");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-12-23 18:28:16 +0100 (Tue, 23 Dec 2008)");
 script_cve_id("CVE-2008-5316", "CVE-2008-5317");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1684-1 (lcms)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"liblcms1-dev", ver:"1.15-1.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"liblcms1", ver:"1.15-1.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"liblcms-utils", ver:"1.15-1.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
