# OpenVAS Vulnerability Test
# $Id: deb_1635_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1635-1 (freetype)
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
tag_insight = "Several local vulnerabilities have been discovered in freetype,
a FreeType 2 font engine, which could allow the execution of arbitrary
code.

The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2008-1806
An integer overflow allows context-dependent attackers to execute
arbitrary code via a crafted set of values within the Private
dictionary table in a Printer Font Binary (PFB) file.

CVE-2008-1807
The handling of an invalid number of axes field in the PFB file could
trigger the freeing of aribtrary memory locations, leading to
memory corruption.

CVE-2008-1808
Multiple off-by-one errors allowed the execution of arbitrary code
via malformed tables in PFB files, or invalid SHC instructions in
TTF files.


For the stable distribution (etch), these problems have been fixed in version
2.2.1-5+etch3.

For the unstable distribution (sid), these problems have been fixed in
version 2.3.6-1.

We recommend that you upgrade your freetype package.";
tag_summary = "The remote host is missing an update to freetype
announced via advisory DSA 1635-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201635-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302087");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-17 04:23:15 +0200 (Wed, 17 Sep 2008)");
 script_cve_id("CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1635-1 (freetype)");



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
if ((res = isdpkgvuln(pkg:"freetype2-demos", ver:"2.2.1-5+etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libfreetype6-dev", ver:"2.2.1-5+etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libfreetype6", ver:"2.2.1-5+etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
