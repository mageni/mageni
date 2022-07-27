# OpenVAS Vulnerability Test
# $Id: deb_1795_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1795-1 (ldns)
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
tag_insight = "Stefan Kaltenbrunner discovered that ldns, a library and set of utilities
to facilitate DNS programming, did not correctly implement a buffer
boundary check in its RR DNS record parser.  This weakness could enable
overflow of a heap buffer if a maliciously-crafted record is parsed,
potentially allowing the execution of arbitrary code.  The scope of
compromise will vary with the context in which ldns is used, and could
present either a local or remote attack vector.

The old stable distribution (etch) is not affected by this issue.

For the stable distribution (lenny), this problem has been fixed in
version 1.4.0-1+lenny1.

For the unstable distribution (sid), this problem was fixed in
version 1.5.1-1.

We recommend that you upgrade your ldns packages.";
tag_summary = "The remote host is missing an update to ldns
announced via advisory DSA 1795-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201795-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311916");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-05-11 20:24:31 +0200 (Mon, 11 May 2009)");
 script_cve_id("CVE-2009-1086");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_name("Debian Security Advisory DSA 1795-1 (ldns)");



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
if ((res = isdpkgvuln(pkg:"ldnsutils", ver:"1.4.0-1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libldns-dev", ver:"1.4.0-1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libldns1", ver:"1.4.0-1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
