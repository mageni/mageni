# OpenVAS Vulnerability Test
# $Id: ubuntu_831_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_831_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-831-1 (openexr)
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
  libopenexr2ldbl                 1.2.2-4.4ubuntu1.1

Ubuntu 8.10:
  libopenexr6                     1.6.1-3ubuntu1.8.10.1

Ubuntu 9.04:
  libopenexr6                     1.6.1-3ubuntu1.9.04.1

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-831-1";

tag_insight = "Drew Yao discovered several flaws in the way OpenEXR handled certain
malformed EXR image files. If a user were tricked into opening a crafted
EXR image file, an attacker could cause a denial of service via application
crash, or possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2009-1720, CVE-2009-1721)

It was discovered that OpenEXR did not properly handle certain malformed
EXR image files. If a user were tricked into opening a crafted EXR image
file, an attacker could cause a denial of service via application crash, or
possibly execute arbitrary code with the privileges of the user invoking
the program. This issue only affected Ubuntu 8.04 LTS. (CVE-2009-1722)";
tag_summary = "The remote host is missing an update to openexr
announced via advisory USN-831-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307288");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-09-15 22:46:32 +0200 (Tue, 15 Sep 2009)");
 script_cve_id("CVE-2009-1720", "CVE-2009-1721", "CVE-2009-1722");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Ubuntu USN-831-1 (openexr)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-831-1/");

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
if ((res = isdpkgvuln(pkg:"libopenexr-dev", ver:"1.2.2-4.4ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopenexr2ldbl", ver:"1.2.2-4.4ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openexr", ver:"1.2.2-4.4ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopenexr-dev", ver:"1.6.1-3ubuntu1.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopenexr6", ver:"1.6.1-3ubuntu1.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openexr", ver:"1.6.1-3ubuntu1.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopenexr-dev", ver:"1.6.1-3ubuntu1.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopenexr6", ver:"1.6.1-3ubuntu1.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openexr", ver:"1.6.1-3ubuntu1.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
