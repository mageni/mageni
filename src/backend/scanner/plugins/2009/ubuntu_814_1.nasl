# OpenVAS Vulnerability Test
# $Id: ubuntu_814_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_814_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-814-1 (openjdk-6)
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

Ubuntu 8.10:
  icedtea6-plugin                 6b12-0ubuntu6.5
  openjdk-6-jre                   6b12-0ubuntu6.5
  openjdk-6-jre-lib               6b12-0ubuntu6.5

Ubuntu 9.04:
  icedtea6-plugin                 6b14-1.4.1-0ubuntu11
  openjdk-6-jre                   6b14-1.4.1-0ubuntu11
  openjdk-6-jre-lib               6b14-1.4.1-0ubuntu11

After a standard system upgrade you need to restart any Java applications
to effect the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-814-1";

tag_insight = "It was discovered that the XML HMAC signature system did not
correctly check certain lengths.  If an attacker sent a truncated
HMAC, it could bypass authentication, leading to potential privilege
escalation. (CVE-2009-0217)

It was discovered that certain variables could leak information.  If a
user were tricked into running a malicious Java applet, a remote attacker
could exploit this gain access to private information and potentially
run untrusted code. (CVE-2009-2475, CVE-2009-2690)

A flaw was discovered the OpenType checking.  If a user were tricked
into running a malicious Java applet, a remote attacker could bypass
access restrictions. (CVE-2009-2476)

It was discovered that the XML processor did not correctly check
recursion.  If a user or automated system were tricked into processing
a specially crafted XML, the system could crash, leading to a denial of
service. (CVE-2009-2625)

It was discovered that the Java audio subsystem did not correctly validate
certain parameters.  If a user were tricked into running an untrusted
applet, a remote attacker could read system properties.  (CVE-2009-2670)

Multiple flaws were discovered in the proxy subsystem.  If a user
were tricked into running an untrusted applet, a remote attacker could
discover local user names, obtain access to sensitive information, or
bypass socket restrictions, leading to a loss of privacy. (CVE-2009-2671,
CVE-2009-2672, CVE-2009-2673)

Flaws were discovered in the handling of JPEG images, Unpack200 archives,
and JDK13Services.  If a user were tricked into running an untrusted
applet, a remote attacker could load a specially crafted file that would
bypass local file access protections and run arbitrary code with user
privileges. (CVE-2009-2674, CVE-2009-2675, CVE-2009-2676, CVE-2009-2689)";
tag_summary = "The remote host is missing an update to openjdk-6
announced via advisory USN-814-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310718");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
 script_cve_id("CVE-2009-0217", "CVE-2009-2475", "CVE-2009-2476", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2676", "CVE-2009-2690", "CVE-2009-2689");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Ubuntu USN-814-1 (openjdk-6)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-814-1/");

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
if ((res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b12-0ubuntu6.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b12-0ubuntu6.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-source", ver:"6b12-0ubuntu6.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-source-files", ver:"6b12-0ubuntu6.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b12-0ubuntu6.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-dbg", ver:"6b12-0ubuntu6.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b12-0ubuntu6.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b12-0ubuntu6.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b12-0ubuntu6.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b12-0ubuntu6.5", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b14-1.4.1-0ubuntu11", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b14-1.4.1-0ubuntu11", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-source", ver:"6b14-1.4.1-0ubuntu11", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-source-files", ver:"6b14-1.4.1-0ubuntu11", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b14-1.4.1-0ubuntu11", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b14-1.4.1-0ubuntu11", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-dbg", ver:"6b14-1.4.1-0ubuntu11", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b14-1.4.1-0ubuntu11", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b14-1.4.1-0ubuntu11", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b14-1.4.1-0ubuntu11", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b14-1.4.1-0ubuntu11", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b14-1.4.1-0ubuntu11", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
