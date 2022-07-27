# OpenVAS Vulnerability Test
# $Id: deb_1189_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1189-1
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
version 3.8.1p1-7sarge1.

For the unstable distribution (sid) these problems have been fixed in
version 4.3p2-4 of openssh. openssh-krb5 will soon be converted towards
a transitional package against openssh.

We recommend that you upgrade your openssh-krb5 packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201189-1";
tag_summary = "The remote host is missing an update to openssh-krb5
announced via advisory DSA 1189-1.

Several remote vulnerabilities have been discovered in OpenSSH, a free
implementation of the Secure Shell protocol, which may lead to denial of
service and potentially the execution of arbitrary code. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-4924

Tavis Ormandy of the Google Security Team discovered a denial of
service vulnerability in the mitigation code against complexity
attacks, which might lead to increased CPU consumption until a
timeout is triggered. This is only exploitable if support for
SSH protocol version 1 is enabled.

CVE-2006-5051

Mark Dowd discovered that insecure signal handler usage could
potentially lead to execution of arbitrary code through a double
free. The Debian Security Team doesn't believe the general openssh
package without Kerberos support to be exploitable by this issue.
However, due to the complexity of the underlying code we will
issue an update to rule out all eventualities.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302216");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:13:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-4924", "CVE-2006-5051");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1189-1 (openssh-krb5)");



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
if ((res = isdpkgvuln(pkg:"ssh-krb5", ver:"3.8.1p1-7sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
