# OpenVAS Vulnerability Test
# $Id: deb_1799_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1799-1 (qemu)
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
tag_insight = "Several vulnerabilities have been discovered in the QEMU processor
emulator. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2008-0928

Ian Jackson discovered that range checks of file operations on
emulated disk devices were insufficiently enforced.

CVE-2008-1945

It was discovered that an error in the format auto detection of
removable media could lead to the disclosure of files in the
host system.

CVE-2008-4539

A buffer overflow has been found in the emulation of the Cirrus
graphics adaptor.


For the old stable distribution (etch), these problems have been fixed in
version 0.8.2-4etch3.

For the stable distribution (lenny), these problems have been fixed in
version 0.9.1-10lenny1.

For the unstable distribution (sid), these problems have been fixed in
version 0.9.1+svn20081101-1.

We recommend that you upgrade your qemu packages.";
tag_summary = "The remote host is missing an update to qemu
announced via advisory DSA 1799-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201799-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306779");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-05-20 00:17:15 +0200 (Wed, 20 May 2009)");
 script_cve_id("CVE-2008-0928", "CVE-2008-4539", "CVE-2008-1945");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1799-1 (qemu)");



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
if ((res = isdpkgvuln(pkg:"qemu", ver:"0.8.2-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qemu", ver:"0.9.1-10lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
