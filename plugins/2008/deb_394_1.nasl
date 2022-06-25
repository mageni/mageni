# OpenVAS Vulnerability Test
# $Id: deb_394_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 394-1
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
tag_insight = "Steve Henson of the OpenSSL core team identified and prepared fixes
for a number of vulnerabilities in the OpenSSL ASN1 code that were
discovered after running a test suite by British National
Infrastructure Security Coordination Centre (NISCC).

A bug in OpenSSLs SSL/TLS protocol was also identified which causes
OpenSSL to parse a client certificate from an SSL/TLS client when it
should reject it as a protocol error.

The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2003-0543:

Integer overflow in OpenSSL that allows remote attackers to cause a
denial of service (crash) via an SSL client certificate with
certain ASN.1 tag values.

CVE-2003-0544:

OpenSSL does not properly track the number of characters in certain
ASN.1 inputs, which allows remote attackers to cause a denial of
service (crash) via an SSL client certificate that causes OpenSSL
to read past the end of a buffer when the long form is used.

CVE-2003-0545:

Double-free vulnerability allows remote attackers to cause a denial
of service (crash) and possibly execute arbitrary code via an SSL
client certificate with a certain invalid ASN.1 encoding.  This bug
was only present in OpenSSL 0.9.7 and is listed here only for
reference.

For the stable distribution (woody) this problem has been
fixed in openssl095 version 0.9.5a-6.woody.3.

This package is not present in the unstable (sid) or testing (sarge)
distribution.

We recommend that you upgrade your libssl095a packages and restart";
tag_summary = "The remote host is missing an update to openssl095
announced via advisory DSA 394-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20394-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301721");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0543", "CVE-2003-0544", "CVE-2003-0545");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 394-1 (openssl095)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"libssl095a", ver:"0.9.5a-6.woody.3", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
