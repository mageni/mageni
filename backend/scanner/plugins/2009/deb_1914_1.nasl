# OpenVAS Vulnerability Test
# $Id: deb_1914_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1914-1 (mapserver)
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
tag_insight = "Several vulnerabilities have been discovered in mapserver, a CGI-based
web framework to publish spatial data and interactive mapping applications.
The Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2009-0843

Missing input validation on a user supplied map queryfile name can be
used by an attacker to check for the existence of a specific file by
using the queryfile GET parameter and checking for differences in error
messages.

CVE-2009-0842

A lack of file type verification when parsing a map file can lead to
partial disclosure of content from arbitrary files through parser error
messages.

CVE-2009-0841

Due to missing input validation when saving map files under certain
conditions it is possible to perform directory traversal attacks and
to create arbitrary files.
NOTE: Unless the attacker is able to create directories in the image
path or there is already a readable directory this doesn't affect
installations on Linux as the fopen() syscall will fail in case a sub
path is not readable.

CVE-2009-0839

It was discovered that mapserver is vulnerable to a stack-based buffer
overflow when processing certain GET parameters.  An attacker can use
this to execute arbitrary code on the server via crafted id parameters.

CVE-2009-0840

An integer overflow leading to a heap-based buffer overflow when
processing the Content-Length header of an HTTP request can be used by an
attacker to execute arbitrary code via crafted POST requests containing
negative Content-Length values.

CVE-2009-2281

An integer overflow when processing HTTP requests can lead to a
heap-based buffer overflow. An attacker can use this to execute arbitrary
code either via crafted Content-Length values or large HTTP request. This
is partly because of an incomplete fix for CVE-2009-0840.


For the oldstable distribution (etch), this problem has been fixed in
version 4.10.0-5.1+etch4.

For the stable distribution (lenny), this problem has been fixed in
version 5.0.3-3+lenny4.

For the testing distribution (squeeze), this problem has been fixed in
version 5.4.2-1.

For the unstable distribution (sid), this problem has been fixed in
version 5.4.2-1.


We recommend that you upgrade your mapserver packages.";
tag_summary = "The remote host is missing an update to mapserver
announced via advisory DSA 1914-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201914-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309294");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-27 01:37:56 +0100 (Tue, 27 Oct 2009)");
 script_cve_id("CVE-2009-0843", "CVE-2009-0842", "CVE-2009-0841", "CVE-2009-0840", "CVE-2009-0839", "CVE-2009-2281");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1914-1 (mapserver)");



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
if ((res = isdpkgvuln(pkg:"mapserver-doc", ver:"4.10.0-5.1+etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cgi-mapserver", ver:"4.10.0-5.1+etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mapserver-bin", ver:"4.10.0-5.1+etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mapscript", ver:"4.10.0-5.1+etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-mapscript", ver:"4.10.0-5.1+etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-mapscript", ver:"4.10.0-5.1+etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"perl-mapscript", ver:"4.10.0-5.1+etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmapscript-ruby", ver:"5.0.3-3+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mapserver-doc", ver:"5.0.3-3+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cgi-mapserver", ver:"5.0.3-3+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-mapscript", ver:"5.0.3-3+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"perl-mapscript", ver:"5.0.3-3+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmapscript-ruby1.9", ver:"5.0.3-3+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mapserver-bin", ver:"5.0.3-3+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mapscript", ver:"5.0.3-3+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmapscript-ruby1.8", ver:"5.0.3-3+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
