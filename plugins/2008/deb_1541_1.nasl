# OpenVAS Vulnerability Test
# $Id: deb_1541_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1541-1 (openldap2.3)
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
tag_insight = "Several remote vulnerabilities have been discovered in OpenLDAP, a
free implementation of the Lightweight Directory Access Protocol. The
Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2007-5707

Thomas Sesselmann discovered that slapd could be crashed by a
malformed modify requests.

CVE-2007-5708

Toby Blade discovered that incorrect memory handling in slapo-pcache
could lead to denial of service through crafted search requests.

CVE-2007-6698

It was discovered that a programming error in the interface to the
BDB storage backend could lead to denial of service through
crafted modify requests.

CVE-2008-0658

It was discovered that a programming error in the interface to the
BDB storage backend could lead to denial of service through
crafted modrdn requests.

For the stable distribution (etch), these problems have been fixed in
version 2.3.30-5+etch1.

For the unstable distribution (sid), these problems have been fixed in
version 2.4.7-6.1.

We recommend that you upgrade your openldap2.3 packages.";
tag_summary = "The remote host is missing an update to openldap2.3
announced via advisory DSA 1541-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201541-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301145");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-04-21 20:40:14 +0200 (Mon, 21 Apr 2008)");
 script_cve_id("CVE-2007-5707", "CVE-2007-5708", "CVE-2007-6698", "CVE-2008-0658");
 script_tag(name:"cvss_base", value:"7.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_name("Debian Security Advisory DSA 1541-1 (openldap2.3)");



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
if ((res = isdpkgvuln(pkg:"ldap-utils", ver:"2.3.30-5+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libldap-2.3-0", ver:"2.3.30-5+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"slapd", ver:"2.3.30-5+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
