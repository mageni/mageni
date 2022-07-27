# OpenVAS Vulnerability Test
# $Id: mdksa_2009_080.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:080 (glib2.0)
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
tag_insight = "Multiple integer overflows in GLib's Base64 encoding and decoding
functions enable attackers (possibly remote ones, depending on
the applications glib2 is linked against with - mostly GNOME ones)
either to cause denial of service and to execute arbitrary code via
an untrusted input (CVE-2008-4316).

This update provide the fix for that security issue.

Affected: 2008.0, 2008.1, 2009.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:080";
tag_summary = "The remote host is missing an update to glib2.0
announced via advisory MDVSA-2009:080.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308933");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-04-06 20:58:11 +0200 (Mon, 06 Apr 2009)");
 script_cve_id("CVE-2008-4316");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Mandrake Security Advisory MDVSA-2009:080 (glib2.0)");



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
if ((res = isrpmvuln(pkg:"glib2.0-common", rpm:"glib2.0-common~2.14.1~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glib-gettextize", rpm:"glib-gettextize~2.14.1~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libglib2.0_0", rpm:"libglib2.0_0~2.14.1~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libglib2.0_0-devel", rpm:"libglib2.0_0-devel~2.14.1~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64glib2.0_0", rpm:"lib64glib2.0_0~2.14.1~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64glib2.0_0-devel", rpm:"lib64glib2.0_0-devel~2.14.1~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glib2.0-common", rpm:"glib2.0-common~2.16.2~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glib-gettextize", rpm:"glib-gettextize~2.16.2~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgio2.0_0", rpm:"libgio2.0_0~2.16.2~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libglib2.0_0", rpm:"libglib2.0_0~2.16.2~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libglib2.0-devel", rpm:"libglib2.0-devel~2.16.2~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gio2.0_0", rpm:"lib64gio2.0_0~2.16.2~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64glib2.0_0", rpm:"lib64glib2.0_0~2.16.2~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64glib2.0-devel", rpm:"lib64glib2.0-devel~2.16.2~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glib2.0-common", rpm:"glib2.0-common~2.18.1~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glib-gettextize", rpm:"glib-gettextize~2.18.1~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgio2.0_0", rpm:"libgio2.0_0~2.18.1~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libglib2.0_0", rpm:"libglib2.0_0~2.18.1~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libglib2.0-devel", rpm:"libglib2.0-devel~2.18.1~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gio2.0_0", rpm:"lib64gio2.0_0~2.18.1~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64glib2.0_0", rpm:"lib64glib2.0_0~2.18.1~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64glib2.0-devel", rpm:"lib64glib2.0-devel~2.18.1~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
