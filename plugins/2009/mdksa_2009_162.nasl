# OpenVAS Vulnerability Test
# $Id: mdksa_2009_162.nasl 6587 2017-07-07 06:35:35Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:162 (java-1.6.0-openjdk)
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
tag_insight = "Multiple security vulnerabilities has been identified and fixed in
Little cms library embedded in OpenJDK:

A memory leak flaw allows remote attackers to cause a denial of service
(memory consumption and application crash) via a crafted image file
(CVE-2009-0581).

Multiple integer overflows allow remote attackers to execute arbitrary
code via a crafted image file that triggers a heap-based buffer
overflow (CVE-2009-0723).

Multiple stack-based buffer overflows allow remote attackers to
execute arbitrary code via a crafted image file associated with a large
integer value for the (1) input or (2) output channel (CVE-2009-0733).

A flaw in the transformations of monochrome profiles allows remote
attackers to cause denial of service triggered by a NULL pointer
dereference via a crafted image file (CVE-2009-0793).

Further security fixes in the JRE and in the Java API of OpenJDK:

A flaw in handling temporary font files by the Java Virtual
Machine (JVM) allows remote attackers to cause denial of service
(CVE-2006-2426).

An integer overflow flaw was found in Pulse-Java when handling Pulse
audio source data lines. An attacker could use this flaw to cause an
applet to crash, leading to a denial of service (CVE-2009-0794).

A flaw in Java Runtime Environment initialized LDAP connections
allows authenticated remote users to cause denial of service on the
LDAP service (CVE-2009-1093).

A flaw in the Java Runtime Environment LDAP client in handling server
LDAP responses allows remote attackers to execute arbitrary code on
the client side via malicious server response (CVE-2009-1094).

Buffer overflows in the the Java Runtime Environment unpack200 utility
allow remote attackers to execute arbitrary code via an crafted applet
(CVE-2009-1095, CVE-2009-1096).

A buffer overflow in the splash screen processing allows a attackers
to execute arbitrary code (CVE-2009-1097).

A buffer overflow in GIF images handling allows remote attackers to
execute arbitrary code via an crafted GIF image (CVE-2009-1098).

A flaw in the Java API for XML Web Services (JAX-WS) service endpoint
handling allows remote attackers to cause a denial of service on the
service endpoint's server side (CVE-2009-1101).

A flaw in the Java Runtime Environment Virtual Machine code generation
allows remote attackers to execute arbitrary code via a crafted applet
(CVE-2009-1102).

This update provides fixes for these issues.

Affected: Enterprise Server 5.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:162";
tag_summary = "The remote host is missing an update to java-1.6.0-openjdk
announced via advisory MDVSA-2009:162.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310134");
 script_version("$Revision: 6587 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 08:35:35 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
 script_cve_id("CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733", "CVE-2009-0793", "CVE-2006-2426", "CVE-2009-0794", "CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1101", "CVE-2009-1102");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Mandrake Security Advisory MDVSA-2009:162 (java-1.6.0-openjdk)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Mandrake Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~0.20.b16.0.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~0.20.b16.0.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~0.20.b16.0.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~0.20.b16.0.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-plugin", rpm:"java-1.6.0-openjdk-plugin~1.6.0.0~0.20.b16.0.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~0.20.b16.0.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rhino", rpm:"rhino~1.7~0.0.2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rhino-demo", rpm:"rhino-demo~1.7~0.0.2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rhino-javadoc", rpm:"rhino-javadoc~1.7~0.0.2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rhino-manual", rpm:"rhino-manual~1.7~0.0.2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
