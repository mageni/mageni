# OpenVAS Vulnerability Test
# $Id: deb_1458_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1458-1 (openafs)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "A race condition in the OpenAFS fileserver allows remote attackers to
cause a denial of service (daemon crash) by simultaneously acquiring and
giving back file callbacks, which causes the handler for the
GiveUpAllCallBacks RPC to perform linked-list operations without the
host_glock lock.

For the stable distribution (etch), this problem has been fixed in
version 1.4.2-6etch1

For the old stable distribution (sarge), this problem has been fixed in
version 1.3.81-3sarge3

We recommend that you upgrade your openafs packages.";
tag_summary = "The remote host is missing an update to openafs
announced via advisory DSA 1458-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201458-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300277");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-31 16:11:48 +0100 (Thu, 31 Jan 2008)");
 script_cve_id("CVE-2007-6599");
 script_bugtraq_id(27132);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_name("Debian Security Advisory DSA 1458-1 (openafs)");



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
if ((res = isdpkgvuln(pkg:"openafs-modules-source", ver:"1.4.2-6etch1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-fileserver", ver:"1.4.2-6etch1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpam-openafs-kaserver", ver:"1.4.2-6etch1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-dbserver", ver:"1.4.2-6etch1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-kpasswd", ver:"1.4.2-6etch1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-client", ver:"1.4.2-6etch1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopenafs-dev", ver:"1.4.2-6etch1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-doc", ver:"1.4.2-6etch1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-krb5", ver:"1.4.2-6etch1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-dbg", ver:"1.4.2-6etch1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
