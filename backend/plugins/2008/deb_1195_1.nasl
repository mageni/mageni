# OpenVAS Vulnerability Test
# $Id: deb_1195_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1195-1
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
tag_solution = "For the stable distribution (sarge) these problems have been fixed in
version 0.9.6m-1sarge4

This package exists only for compatibility with older software, and is
not present in the unstable or testing branches of Debian.

We recommend that you upgrade your openssl096 package.  Note that

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201195-1";
tag_summary = "The remote host is missing an update to openssl096
announced via advisory DSA 1195-1.

Multiple vulnerabilities have been discovered in the OpenSSL
cryptographic software package that could allow an attacker to launch
a denial of service attack by exhausting system resources or crashing
processes on a victim's computer.

CVE-2006-3738
Tavis Ormandy and Will Drewry of the Google Security Team
discovered a buffer overflow in SSL_get_shared_ciphers utility
function, used by some applications such as exim and mysql.  An
attacker could send a list of ciphers that would overrun a
buffer.

CVE-2006-4343
Tavis Ormandy and Will Drewry of the Google Security Team
discovered a possible DoS in the sslv2 client code.  Where a
client application uses OpenSSL to make a SSLv2 connection to
a malicious server that server could cause the client to
crash.

CVE-2006-2940
Dr S N Henson of the OpenSSL core team and Open Network
Security recently developed an ASN1 test suite for NISCC
(www.niscc.gov.uk). When the test suite was run against
OpenSSL a DoS was discovered.

Certain types of public key can take disproportionate amounts
of time to process. This could be used by an attacker in a
denial of service attack.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301363");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:13:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1195-1 (openssl096)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"libssl0.9.6", ver:"0.9.6m-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
