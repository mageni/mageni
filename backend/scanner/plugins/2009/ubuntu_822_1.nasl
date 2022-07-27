# OpenVAS Vulnerability Test
# $Id: ubuntu_822_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_822_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-822-1 (kdelibs)
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

Ubuntu 8.04 LTS:
  kdelibs4c2a                     4:3.5.10-0ubuntu1~hardy1.2

Ubuntu 8.10:
  kdelibs4c2a                     4:3.5.10-0ubuntu6.1
  kdelibs5                        4:4.1.4-0ubuntu1~intrepid1.2

Ubuntu 9.04:
  kdelibs4c2a                     4:3.5.10.dfsg.1-1ubuntu8.1
  kdelibs5                        4:4.2.2-0ubuntu5.1

After a standard system upgrade you need to restart your session to effect
the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-822-1";

tag_insight = "It was discovered that KDE-Libs did not properly handle certain malformed
SVG images. If a user were tricked into opening a specially crafted SVG
image, an attacker could cause a denial of service or possibly execute
arbitrary code with the privileges of the user invoking the program. This
issue only affected Ubuntu 9.04. (CVE-2009-0945)

It was discovered that the KDE JavaScript garbage collector did not
properly handle memory allocation failures. If a user were tricked into
viewing a malicious website, an attacker could cause a denial of service or
possibly execute arbitrary code with the privileges of the user invoking
the program. (CVE-2009-1687)

It was discovered that KDE-Libs did not properly handle HTML content in the
head element. If a user were tricked into viewing a malicious website, an
attacker could cause a denial of service or possibly execute arbitrary code
with the privileges of the user invoking the program. (CVE-2009-1690)

It was discovered that KDE-Libs did not properly handle the Cascading Style
Sheets (CSS) attr function call. If a user were tricked into viewing a
malicious website, an attacker could cause a denial of service or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2009-1698)";
tag_summary = "The remote host is missing an update to kdelibs
announced via advisory USN-822-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305547");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
 script_cve_id("CVE-2009-0945", "CVE-2009-1687", "CVE-2009-1690", "CVE-2009-1698");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Ubuntu USN-822-1 (kdelibs)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-822-1/");

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
if ((res = isdpkgvuln(pkg:"kdelibs-data", ver:"3.5.10-0ubuntu1~hardy1.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs4-doc", ver:"3.5.10-0ubuntu1~hardy1.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs", ver:"3.5.10-0ubuntu1~hardy1.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs-dbg", ver:"3.5.10-0ubuntu1~hardy1.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs4-dev", ver:"3.5.10-0ubuntu1~hardy1.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs4c2a", ver:"3.5.10-0ubuntu1~hardy1.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs5-data", ver:"4.1.4-0ubuntu1~intrepid1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs5-doc", ver:"4.1.4-0ubuntu1~intrepid1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs-data", ver:"3.5.10-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs4-doc", ver:"3.5.10-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs", ver:"3.5.10-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs-bin", ver:"4.1.4-0ubuntu1~intrepid1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs5-dbg", ver:"4.1.4-0ubuntu1~intrepid1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs5-dev", ver:"4.1.4-0ubuntu1~intrepid1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs5", ver:"4.1.4-0ubuntu1~intrepid1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs-dbg", ver:"3.5.10-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs4-dev", ver:"3.5.10-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs4c2a", ver:"3.5.10-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs5-data", ver:"4.2.2-0ubuntu5.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs-data", ver:"3.5.10.dfsg.1-1ubuntu8.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs", ver:"3.5.10.dfsg.1-1ubuntu8.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs-bin", ver:"4.2.2-0ubuntu5.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs5-dbg", ver:"4.2.2-0ubuntu5.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs5-dev", ver:"4.2.2-0ubuntu5.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs5", ver:"4.2.2-0ubuntu5.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libplasma-dev", ver:"4.2.2-0ubuntu5.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libplasma3", ver:"4.2.2-0ubuntu5.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs-dbg", ver:"3.5.10.dfsg.1-1ubuntu8.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs4-dev", ver:"3.5.10.dfsg.1-1ubuntu8.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs4c2a", ver:"3.5.10.dfsg.1-1ubuntu8.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
