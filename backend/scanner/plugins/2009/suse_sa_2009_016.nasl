# OpenVAS Vulnerability Test
# $Id: suse_sa_2009_016.nasl 6668 2017-07-11 13:34:29Z cfischer $
# Description: Auto-generated from advisory SUSE-SA:2009:016 (Sun Java 5 and 6)
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
tag_insight = "The Sun JDK 5 was updated to Update18 and the Sun JDK 6 was updated
to Update 13 to fix various bugs and security issues.

For details addressed in these updates, please visit the referenced
security advisories.

No Sun Java 1.4.2 updates are available at this time since it has
entered EOL phase.";
tag_solution = "Update your system with the packages as indicated in
the referenced security advisory.

https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:016";
tag_summary = "The remote host is missing updates announced in
advisory SUSE-SA:2009:016.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309563");
 script_version("$Revision: 6668 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-11 15:34:29 +0200 (Tue, 11 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-04-06 20:58:11 +0200 (Mon, 06 Apr 2009)");
 script_cve_id("CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1099", "CVE-2009-1100", "CVE-2009-1101", "CVE-2009-1102", "CVE-2009-1103", "CVE-2009-1104", "CVE-2009-1105", "CVE-2009-1106", "CVE-2009-1107");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("SuSE Security Advisory SUSE-SA:2009:016 (Sun Java 5 and 6)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("SuSE Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
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
if ((res = isrpmvuln(pkg:"java-1_5_0-sun", rpm:"java-1_5_0-sun~1.5.0_update18~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-alsa", rpm:"java-1_5_0-sun-alsa~1.5.0_update18~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-devel", rpm:"java-1_5_0-sun-devel~1.5.0_update18~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-jdbc", rpm:"java-1_5_0-sun-jdbc~1.5.0_update18~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-plugin", rpm:"java-1_5_0-sun-plugin~1.5.0_update18~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-src", rpm:"java-1_5_0-sun-src~1.5.0_update18~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun", rpm:"java-1_6_0-sun~1.6.0.u13~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-alsa", rpm:"java-1_6_0-sun-alsa~1.6.0.u13~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-devel", rpm:"java-1_6_0-sun-devel~1.6.0.u13~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-jdbc", rpm:"java-1_6_0-sun-jdbc~1.6.0.u13~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-plugin", rpm:"java-1_6_0-sun-plugin~1.6.0.u13~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-src", rpm:"java-1_6_0-sun-src~1.6.0.u13~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun", rpm:"java-1_5_0-sun~1.5.0_update18~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-alsa", rpm:"java-1_5_0-sun-alsa~1.5.0_update18~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-demo", rpm:"java-1_5_0-sun-demo~1.5.0_update18~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-devel", rpm:"java-1_5_0-sun-devel~1.5.0_update18~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-jdbc", rpm:"java-1_5_0-sun-jdbc~1.5.0_update18~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-plugin", rpm:"java-1_5_0-sun-plugin~1.5.0_update18~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-src", rpm:"java-1_5_0-sun-src~1.5.0_update18~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun", rpm:"java-1_6_0-sun~1.6.0.u13~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-alsa", rpm:"java-1_6_0-sun-alsa~1.6.0.u13~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-demo", rpm:"java-1_6_0-sun-demo~1.6.0.u13~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-devel", rpm:"java-1_6_0-sun-devel~1.6.0.u13~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-jdbc", rpm:"java-1_6_0-sun-jdbc~1.6.0.u13~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-plugin", rpm:"java-1_6_0-sun-plugin~1.6.0.u13~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-src", rpm:"java-1_6_0-sun-src~1.6.0.u13~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun", rpm:"java-1_5_0-sun~1.5.0_update18~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-alsa", rpm:"java-1_5_0-sun-alsa~1.5.0_update18~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-demo", rpm:"java-1_5_0-sun-demo~1.5.0_update18~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-devel", rpm:"java-1_5_0-sun-devel~1.5.0_update18~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-jdbc", rpm:"java-1_5_0-sun-jdbc~1.5.0_update18~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-plugin", rpm:"java-1_5_0-sun-plugin~1.5.0_update18~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-src", rpm:"java-1_5_0-sun-src~1.5.0_update18~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun", rpm:"java-1_6_0-sun~1.6.0.u12~1.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-alsa", rpm:"java-1_6_0-sun-alsa~1.6.0.u12~1.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-debuginfo", rpm:"java-1_6_0-sun-debuginfo~1.6.0.u12~1.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-demo", rpm:"java-1_6_0-sun-demo~1.6.0.u12~1.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-devel", rpm:"java-1_6_0-sun-devel~1.6.0.u12~1.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-jdbc", rpm:"java-1_6_0-sun-jdbc~1.6.0.u12~1.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-plugin", rpm:"java-1_6_0-sun-plugin~1.6.0.u12~1.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-src", rpm:"java-1_6_0-sun-src~1.6.0.u12~1.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
