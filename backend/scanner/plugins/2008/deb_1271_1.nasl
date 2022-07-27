# OpenVAS Vulnerability Test
# $Id: deb_1271_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1271-1
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
tag_solution = "For the stable distribution (sarge), this problem has been fixed in
version 1.3.81-3sarge2.  For the unstable distribution (sid) and the
upcoming stable distribution (etch), this problem will be fixed in
version 1.4.2-6.

We recommend that you upgrade your openafs package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201271-1";
tag_summary = "The remote host is missing an update to openafs
announced via advisory DSA 1271-1.

A design error has been identified in the OpenAFS, a cross-platform
distributed filesystem included with Debian.

OpenAFS historically has enabled setuid filesystem support for the local
cell.  However, with its existing protocol, OpenAFS can only use
encryption, and therefore integrity protection, if the user is
authenticated.  Unauthenticated access doesn't do integrity protection.
The practical result is that it's possible for an attacker with
knowledge of AFS to forge an AFS FetchStatus call and make an arbitrary
binary file appear to an AFS client host to be setuid.  If they can then
arrange for that binary to be executed, they will be able to achieve
privilege escalation.

OpenAFS 1.3.81-3sarge2 changes the default behavior to disable setuid
files globally, including the local cell.  It is important to note that
this change will not take effect until the AFS kernel module, built from
the openafs-modules-source package, is rebuilt and loaded into your
kernel.  As a temporary workaround until the kernel module can be
reloaded, setuid support can be manually disabled for the local cell by
running the following command as root

fs setcell -cell <localcell> -nosuid

Following the application of this update, if you are certain there is
no security risk of an attacker forging AFS fileserver responses, you
can re-enable setuid status selectively with the following command,
however this should not be done on sites that are visible to the
Internet

fs setcell -cell <localcell> -suid";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300186");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:17:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-1507");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1271-1 (openafs)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"openafs-modules-source", ver:"1.3.81-3sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-fileserver", ver:"1.3.81-3sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-client", ver:"1.3.81-3sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-kpasswd", ver:"1.3.81-3sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-dbserver", ver:"1.3.81-3sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpam-openafs-kaserver", ver:"1.3.81-3sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopenafs-dev", ver:"1.3.81-3sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
