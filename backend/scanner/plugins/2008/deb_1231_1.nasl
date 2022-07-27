# OpenVAS Vulnerability Test
# $Id: deb_1231_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1231-1
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
version 1.4.1-1.sarge6.

For the upcoming stable distribution (etch) these problems have been
fixed in version 1.4.6-1.

For the unstable distribution (sid) these problems have been fixed in
version 1.4.6-1.

We recommend that you upgrade your gnupg packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201231-1";
tag_summary = "The remote host is missing an update to gnupg
announced via advisory DSA 1231-1.

Several remote vulnerabilities have been discovered in the GNU privacy,
a free PGP replacement, which may lead to the execution of arbitrary code.
The Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2006-6169

Werner Koch discovered that a buffer overflow in a sanitising function
may lead to execution of arbitrary code when running gnupg
interactively.

CVE-2006-6235

Tavis Ormandy discovered that parsing a carefully crafted OpenPGP
packet may lead to the execution of arbitrary code, as a function
pointer of an internal structure may be controlled through the
decryption routines.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303127");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:17:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-6169", "CVE-2006-6235");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1231-1 (gnupg)");



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
if ((res = isdpkgvuln(pkg:"gnupg", ver:"1.4.1-1.sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
