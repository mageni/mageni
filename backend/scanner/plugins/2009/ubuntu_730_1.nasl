# OpenVAS Vulnerability Test
# $Id: ubuntu_730_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_730_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-730-1 (libpng)
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
tag_solution = "The problem can be corrected by upgrading your system to the
 following package versions:

Ubuntu 6.06 LTS:
  libpng12-0                      1.2.8rel-5ubuntu0.4

Ubuntu 7.10:
  libpng12-0                      1.2.15~beta5-2ubuntu0.2

Ubuntu 8.04 LTS:
  libpng12-0                      1.2.15~beta5-3ubuntu0.1

Ubuntu 8.10:
  libpng12-0                      1.2.27-1ubuntu0.1

After a standard system upgrade you need to reboot your computer to
effect the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-730-1";

tag_insight = "It was discovered that libpng did not properly perform bounds checking in
certain operations. An attacker could send a specially crafted PNG image and
cause a denial of service in applications linked against libpng. This issue
only affected Ubuntu 8.04 LTS. (CVE-2007-5268, CVE-2007-5269)

Tavis Ormandy discovered that libpng did not properly initialize memory. If a
user or automated system were tricked into opening a crafted PNG image, an
attacker could cause a denial of service via application crash, or possibly
execute arbitrary code with the privileges of the user invoking the program.
This issue did not affect Ubuntu 8.10. (CVE-2008-1382)

Harald van Dijk discovered an off-by-one error in libpng. An attacker could
could cause an application crash in programs using pngtest. (CVE-2008-3964)

It was discovered that libpng did not properly NULL terminate a keyword
string. An attacker could exploit this to set arbitrary memory locations to
zero. (CVE-2008-5907)

Glenn Randers-Pehrson discovered that libpng did not properly initialize
pointers. If a user or automated system were tricked into opening a crafted PNG
file, an attacker could cause a denial of service or possibly execute arbitrary
code with the privileges of the user invoking the program. (CVE-2009-0040)";
tag_summary = "The remote host is missing an update to libpng
announced via advisory USN-730-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309790");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-03-07 21:47:03 +0100 (Sat, 07 Mar 2009)");
 script_cve_id("CVE-2007-5268", "CVE-2007-5269", "CVE-2008-1382", "CVE-2008-3964", "CVE-2008-5907", "CVE-2009-0040");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Ubuntu USN-730-1 (libpng)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-730-1/");

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"libpng3", ver:"1.2.8rel-5ubuntu0.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng12-0", ver:"1.2.8rel-5ubuntu0.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng12-dev", ver:"1.2.8rel-5ubuntu0.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng3", ver:"1.2.15~beta5-2ubuntu0.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng12-0", ver:"1.2.15~beta5-2ubuntu0.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng12-dev", ver:"1.2.15~beta5-2ubuntu0.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng3", ver:"1.2.15~beta5-3ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng12-0", ver:"1.2.15~beta5-3ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng12-dev", ver:"1.2.15~beta5-3ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng3", ver:"1.2.27-1ubuntu0.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng12-0", ver:"1.2.27-1ubuntu0.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng12-dev", ver:"1.2.27-1ubuntu0.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
