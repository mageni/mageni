# OpenVAS Vulnerability Test
# $Id: deb_1399_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1399-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
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
tag_insight = "Tavis Ormandy of the Google Security Team has discovered several
security issues in PCRE, the Perl-Compatible Regular Expression library,
which potentially allow attackers to execute arbitrary code by compiling
specially crafted regular expressions.

Version 7.0 of the PCRE library featured a major rewrite of the regular
expression compiler, and it was deemed infeasible to backport the
security fixes in version 7.3 to the versions in Debian's stable and
oldstable distributions (6.7 and 4.5, respectively).  Therefore, this
update contains version 7.3, with special patches to improve the
compatibility with the older versions.  As a result, extra care is
necessary when applying this update.

The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2007-1659

Unmatched \Q\E sequences with orphan \E codes can cause the compiled
regex to become desynchronized, resulting in corrupt bytecode that may
result in multiple exploitable conditions.

CVE-2007-1660

Multiple forms of character class had their sizes miscalculated on
initial passes, resulting in too little memory being allocated.

CVE-2007-1661

Multiple patterns of the form  \X?\d or \P{L}?\d in non-UTF-8 mode
could backtrack before the start of the string, possibly leaking
information from the address space, or causing a crash by reading out
of bounds.

CVE-2007-1662

A number of routines can be fooled into reading past the end of an
string looking for unmatched parentheses or brackets, resulting in a
denial of service.

CVE-2007-4766

Multiple integer overflows in the processing of escape sequences could
result in heap overflows or out of bounds reads/writes.

CVE-2007-4767

Multiple infinite loops and heap overflows were disovered in the
handling of \P and \P{x} sequences, where the length of these
non-standard operations was mishandled.

CVE-2007-4768

Character classes containing a lone unicode sequence were incorrectly
optimised, resulting in a heap overflow.

For the stable distribution (etch), these problems have been fixed in
version 6.7+7.4-2.

For the old stable distribution (sarge), these problems have been fixed in
version 4.5+7.4-1.

For the unstable distribution (sid), these problems have been fixed in
version 7.3-1.";
tag_summary = "The remote host is missing an update to pcre3
announced via advisory DSA 1399-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201399-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303547");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-1659", "CVE-2007-1660", "CVE-2007-1661", "CVE-2007-1662", "CVE-2007-4766", "CVE-2007-4767", "CVE-2007-4768");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1399-1 (pcre3)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"pgrep", ver:"4.5+7.4-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpcre3-dev", ver:"4.5+7.4-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpcre3", ver:"4.5+7.4-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcregrep", ver:"4.5+7.4-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpcrecpp0", ver:"6.7+7.4-2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpcre3-dev", ver:"6.7+7.4-2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcregrep", ver:"6.7+7.4-2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpcre3", ver:"6.7+7.4-2", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
