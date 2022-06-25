# OpenVAS Vulnerability Test
# $Id: deb_1879_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1879-1 (silc-client/silc-toolkit)
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
tag_insight = "Several vulnerabilities have been discovered in the software suite for the
SILC protocol, a network protocol designed to provide end-to-end security
for conferencing services.  The Common Vulnerabilities and Exposures
project identifies the following problems:

An incorrect format string in sscanf() used in the ASN1 encoder to scan an
OID value could overwrite a neighbouring variable on the stack as the
destination data type is smaller than the source type on 64-bit. On 64-bit
architectures this could result in unexpected application behaviour or even
code execution in some cases (CVE-2008-7159).

Various format string vulnerabilities when handling parsed SILC messages
allow an attacker to execute arbitrary code with the rights of the victim
running the SILC client via crafted nick names or channel names containing
format strings (CVE-2009-3051).

An incorrect format string in a sscanf() call used in the HTTP server
component of silcd could result in overwriting a neighbouring variable on
the stack as the destination data type is smaller than the source type on
64-bit.  An attacker could exploit this by using crafted Content-Length
header values resulting in unexpected application behaviour or even code
execution in some cases (CVE-2008-7160).


silc-server doesn't need an update as it uses the shared library provided
by silc-toolkit. silc-client/silc-toolkit in the oldstable distribution
(etch) is not affected by this problem.

For the stable distribution (lenny), this problem has been fixed in
version 1.1.7-2+lenny1 of silc-toolkit and in version 1.1.4-1+lenny1
of silc-client.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 1.1.10-1 of silc-toolkit and version 1.1-2 of silc-client
(using libsilc from silc-toolkit since this upload).

We recommend that you upgrade your silc-toolkit/silc-client packages.";
tag_summary = "The remote host is missing an update to silc-client/silc-toolkit
announced via advisory DSA 1879-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201879-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309396");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-09-09 02:15:49 +0200 (Wed, 09 Sep 2009)");
 script_cve_id("CVE-2008-7159", "CVE-2008-7160", "CVE-2009-3051");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1879-1 (silc-client/silc-toolkit)");



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
if ((res = isdpkgvuln(pkg:"libsilc-1.1-2-dbg", ver:"1.1.7-2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irssi-plugin-silc", ver:"1.1.4-1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsilc-1.1-2-dev", ver:"1.1.7-2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsilc-1.1-2", ver:"1.1.7-2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"silc", ver:"1.1.4-1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
