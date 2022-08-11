# OpenVAS Vulnerability Test
# $Id: deb_1011_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1011-1
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
tag_solution = "For the stable distribution (sarge) this problem has been fixed in
version 1.9.5.5 of kernel-patch-vserver and in version
0.30.204-5sarge3 of util-vserver.

For the unstable distribution (sid) this problem has been fixed in
version 2.3 of kernel-patch-vserver and in version 0.30.208-1 of
util-vserver.

We recommend that you upgrade your util-vserver and

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201011-1";
tag_summary = "The remote host is missing an update to kernel-patch-vserver, util-vserver
announced via advisory DSA 1011-1.

Several vulnerabilities have been discovered in the Debian vserver
support for Linux.  The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2005-4347

Bjørn Steinbrink discovered that the chroot barrier is not set
correctly with util-vserver which may result in unauthorised
escapes from a vserver to the host system.

This vulnerability is limited to the 2.4 kernel patch included in
kernel-patch-vserver.  The correction to this problem requires
updating the util-vserver package as well and installing a new
kernel built from the updated kernel-patch-vserver package.

CVE-2005-4418

The default policy of util-vserver is set to trust all unknown
capabilities instead of considering them as insecure.

The old stable distribution (woody) does not contain a
kernel-patch-vserver package.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303135");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:09:45 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-4347", "CVE-2005-4418");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1011-1 (kernel-patch-vserver, util-vserver)");



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
if ((res = isdpkgvuln(pkg:"kernel-patch-vserver", ver:"1.9.5.5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"util-vserver", ver:"0.30.204-5sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
