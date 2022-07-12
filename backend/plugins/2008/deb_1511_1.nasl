# OpenVAS Vulnerability Test
# $Id: deb_1511_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1511-1 (libicu)
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
tag_insight = "Several local vulnerabilities have been discovered in libicu,
International Components for Unicode, The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2007-4770
libicu in International Components for Unicode (ICU) 3.8.1 and earlier
attempts to process backreferences to the nonexistent capture group
zero (aka \0), which might allow context-dependent attackers to read
from, or write to, out-of-bounds memory locations, related to
corruption of REStackFrames.

CVE-2007-4771
Heap-based buffer overflow in the doInterval function in regexcmp.cpp
in libicu in International Components for Unicode (ICU) 3.8.1 and
earlier allows context-dependent attackers to cause a denial of
service (memory consumption) and possibly have unspecified other
impact via a regular expression that writes a large amount of data to
the backtracking stack.

For the stable distribution (etch), these problems have been fixed in
version 3.6-2etch1.

For the unstable distribution (sid), these problems have been fixed in
version 3.8-6.

We recommend that you upgrade your libicu package.";
tag_summary = "The remote host is missing an update to libicu
announced via advisory DSA 1511-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201511-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302055");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-03-11 21:16:32 +0100 (Tue, 11 Mar 2008)");
 script_cve_id("CVE-2007-4770", "CVE-2007-4771");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1511-1 (libicu)");



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
if ((res = isdpkgvuln(pkg:"icu-doc", ver:"3.6-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libicu36-dev", ver:"3.6-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libicu36", ver:"3.6-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
