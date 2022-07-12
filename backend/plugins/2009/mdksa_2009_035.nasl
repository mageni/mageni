# OpenVAS Vulnerability Test
# $Id: mdksa_2009_035.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:035 (gstreamer0.10-plugins-good)
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
tag_insight = "Security vulnerabilities have been discovered and corrected in
gstreamer0.10-plugins-good, might allow remote attackers to execute
arbitrary code via a malformed QuickTime media file (CVE-2009-0386,
CVE-2009-0387, CVE-2009-0397).

The updated packages have been patched to prevent this.

Affected: 2008.0, 2008.1, 2009.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:035";
tag_summary = "The remote host is missing an update to gstreamer0.10-plugins-good
announced via advisory MDVSA-2009:035.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308876");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
 script_cve_id("CVE-2009-0386", "CVE-2009-0387", "CVE-2009-0397");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Mandrake Security Advisory MDVSA-2009:035 (gstreamer0.10-plugins-good)");



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
if ((res = isrpmvuln(pkg:"gstreamer0.10-aalib", rpm:"gstreamer0.10-aalib~0.10.6~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-caca", rpm:"gstreamer0.10-caca~0.10.6~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-dv", rpm:"gstreamer0.10-dv~0.10.6~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-esound", rpm:"gstreamer0.10-esound~0.10.6~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-flac", rpm:"gstreamer0.10-flac~0.10.6~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-plugins-good", rpm:"gstreamer0.10-plugins-good~0.10.6~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-raw1394", rpm:"gstreamer0.10-raw1394~0.10.6~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-speex", rpm:"gstreamer0.10-speex~0.10.6~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-wavpack", rpm:"gstreamer0.10-wavpack~0.10.6~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-aalib", rpm:"gstreamer0.10-aalib~0.10.7~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-caca", rpm:"gstreamer0.10-caca~0.10.7~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-dv", rpm:"gstreamer0.10-dv~0.10.7~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-esound", rpm:"gstreamer0.10-esound~0.10.7~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-flac", rpm:"gstreamer0.10-flac~0.10.7~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-plugins-good", rpm:"gstreamer0.10-plugins-good~0.10.7~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-raw1394", rpm:"gstreamer0.10-raw1394~0.10.7~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-speex", rpm:"gstreamer0.10-speex~0.10.7~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-wavpack", rpm:"gstreamer0.10-wavpack~0.10.7~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-aalib", rpm:"gstreamer0.10-aalib~0.10.10~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-caca", rpm:"gstreamer0.10-caca~0.10.10~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-dv", rpm:"gstreamer0.10-dv~0.10.10~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-esound", rpm:"gstreamer0.10-esound~0.10.10~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-flac", rpm:"gstreamer0.10-flac~0.10.10~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-plugins-good", rpm:"gstreamer0.10-plugins-good~0.10.10~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-pulse", rpm:"gstreamer0.10-pulse~0.10.10~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-raw1394", rpm:"gstreamer0.10-raw1394~0.10.10~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-soup", rpm:"gstreamer0.10-soup~0.10.10~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-speex", rpm:"gstreamer0.10-speex~0.10.10~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-wavpack", rpm:"gstreamer0.10-wavpack~0.10.10~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
