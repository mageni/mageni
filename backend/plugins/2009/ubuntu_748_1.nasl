# OpenVAS Vulnerability Test
# $Id: ubuntu_748_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_748_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-748-1 (openjdk-6)
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
  icedtea6-plugin                 6b12-0ubuntu6.4
  openjdk-6-jdk                   6b12-0ubuntu6.4
  openjdk-6-jre                   6b12-0ubuntu6.4
  openjdk-6-jre-headless          6b12-0ubuntu6.4
  openjdk-6-jre-lib               6b12-0ubuntu6.4

After a standard system upgrade you need to restart any Java applications
to effect the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-748-1";

tag_insight = "It was discovered that font creation could leak temporary files.
If a user were tricked into loading a malicious program or applet,
a remote attacker could consume disk space, leading to a denial of
service. (CVE-2006-2426, CVE-2009-1100)

It was discovered that the lightweight HttpServer did not correctly close
files on dataless connections.  A remote attacker could send specially
crafted requests, leading to a denial of service. (CVE-2009-1101)

Certain 64bit Java actions would crash an application.  A local attacker
might be able to cause a denial of service. (CVE-2009-1102)

It was discovered that LDAP connections did not close correctly.
A remote attacker could send specially crafted requests, leading to a
denial of service.  (CVE-2009-1093)

Java LDAP routines did not unserialize certain data correctly.  A remote
attacker could send specially crafted requests that could lead to
arbitrary code execution. (CVE-2009-1094)

Java did not correctly check certain JAR headers.  If a user or
automated system were tricked into processing a malicious JAR file,
a remote attacker could crash the application, leading to a denial of
service. (CVE-2009-1095, CVE-2009-1096)

It was discovered that PNG and GIF decoding in Java could lead to memory
corruption.  If a user or automated system were tricked into processing
a specially crafted image, a remote attacker could crash the application,
leading to a denial of service. (CVE-2009-1097, CVE-2009-1098)";
tag_summary = "The remote host is missing an update to openjdk-6
announced via advisory USN-748-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310661");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-04-06 20:58:11 +0200 (Mon, 06 Apr 2009)");
 script_cve_id("CVE-2006-2426", "CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1100", "CVE-2009-1101", "CVE-2009-1102");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Ubuntu USN-748-1 (openjdk-6)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-748-1/");

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
if ((res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b12-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b12-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-source", ver:"6b12-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-source-files", ver:"6b12-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b12-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-dbg", ver:"6b12-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b12-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b12-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b12-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b12-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
