# OpenVAS Vulnerability Test
# $Id: ubuntu_806_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_806_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-806-1 (python2.5)
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
  python2.4                       2.4.3-0ubuntu6.3
  python2.4-minimal               2.4.3-0ubuntu6.3

Ubuntu 8.04 LTS:
  python2.4                       2.4.5-1ubuntu4.2
  python2.4-minimal               2.4.5-1ubuntu4.2
  python2.5                       2.5.2-2ubuntu6
  python2.5-minimal               2.5.2-2ubuntu6

Ubuntu 8.10:
  python2.4                       2.4.5-5ubuntu1.1
  python2.4-minimal               2.4.5-5ubuntu1.1

After a standard system upgrade you need to reboot your computer to
effect the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-806-1";

tag_insight = "It was discovered that Python incorrectly handled certain arguments in the
imageop module. If an attacker were able to pass specially crafted
arguments through the crop function, they could execute arbitrary code with
user privileges. For Python 2.5, this issue only affected Ubuntu 8.04 LTS.
(CVE-2008-4864)

Multiple integer overflows were discovered in Python's stringobject and
unicodeobject expandtabs method. If an attacker were able to exploit these
flaws they could execute arbitrary code with user privileges or cause
Python applications to crash, leading to a denial of service.
(CVE-2008-5031)";
tag_summary = "The remote host is missing an update to python2.5
announced via advisory USN-806-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309934");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
 script_cve_id("CVE-2008-4864", "CVE-2008-5031");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Ubuntu USN-806-1 (python2.5)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-806-1/");

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
if ((res = isdpkgvuln(pkg:"idle-python2.4", ver:"2.4.3-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-doc", ver:"2.4.3-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-examples", ver:"2.4.3-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-dbg", ver:"2.4.3-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-dev", ver:"2.4.3-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-gdbm", ver:"2.4.3-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-minimal", ver:"2.4.3-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-tk", ver:"2.4.3-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4", ver:"2.4.3-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-doc", ver:"2.4.5-1ubuntu4.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-examples", ver:"2.4.5-1ubuntu4.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.5-doc", ver:"2.5.2-2ubuntu6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.5-examples", ver:"2.5.2-2ubuntu6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"idle-python2.4", ver:"2.4.5-1ubuntu4.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"idle-python2.5", ver:"2.5.2-2ubuntu6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-dbg", ver:"2.4.5-1ubuntu4.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-dev", ver:"2.4.5-1ubuntu4.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-minimal", ver:"2.4.5-1ubuntu4.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4", ver:"2.4.5-1ubuntu4.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.5-dbg", ver:"2.5.2-2ubuntu6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.5-dev", ver:"2.5.2-2ubuntu6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.5-minimal", ver:"2.5.2-2ubuntu6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.5", ver:"2.5.2-2ubuntu6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-doc", ver:"2.4.5-5ubuntu1.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-examples", ver:"2.4.5-5ubuntu1.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"idle-python2.4", ver:"2.4.5-5ubuntu1.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-dbg", ver:"2.4.5-5ubuntu1.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-dev", ver:"2.4.5-5ubuntu1.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-minimal", ver:"2.4.5-5ubuntu1.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4", ver:"2.4.5-5ubuntu1.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
