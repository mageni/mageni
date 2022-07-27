# OpenVAS Vulnerability Test
# $Id: mdksa_2009_298.nasl 6587 2017-07-07 06:35:35Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:298 (xine-lib)
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
tag_insight = "Vulnerabilities have been discovered and corrected in xine-lib:

- xine-lib before 1.1.15 allows remote attackers to cause a denial
of service (crash) via mp3 files with metadata consisting only of
separators (CVE-2008-5248)

- Integer overflow in the qt_error parse_trak_atom function in
demuxers/demux_qt.c in xine-lib 1.1.16.2 and earlier allows remote
attackers to execute arbitrary code via a Quicktime movie file with a
large count value in an STTS atom, which triggers a heap-based buffer
overflow (CVE-2009-1274)

- Integer overflow in the 4xm demuxer (demuxers/demux_4xm.c)
in xine-lib 1.1.16.1 allows remote attackers to cause a denial of
service (crash) and possibly execute arbitrary code via a 4X movie
file with a large current_track value, a similar issue to CVE-2009-0385
(CVE-2009-0698)

This update fixes these issues.

Affected: Corporate 3.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:298";
tag_summary = "The remote host is missing an update to xine-lib
announced via advisory MDVSA-2009:298.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311119");
 script_version("$Revision: 6587 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 08:35:35 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-11-17 21:42:12 +0100 (Tue, 17 Nov 2009)");
 script_cve_id("CVE-2008-5248", "CVE-2009-1274", "CVE-2009-0385", "CVE-2009-0698");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Mandriva Security Advisory MDVSA-2009:298 (xine-lib)");



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
if ((res = isrpmvuln(pkg:"libxine1", rpm:"libxine1~1~0.rc3.6.18.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxine1-devel", rpm:"libxine1-devel~1~0.rc3.6.18.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-aa", rpm:"xine-aa~1~0.rc3.6.18.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-arts", rpm:"xine-arts~1~0.rc3.6.18.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-dxr3", rpm:"xine-dxr3~1~0.rc3.6.18.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-esd", rpm:"xine-esd~1~0.rc3.6.18.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-flac", rpm:"xine-flac~1~0.rc3.6.18.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-gnomevfs", rpm:"xine-gnomevfs~1~0.rc3.6.18.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-plugins", rpm:"xine-plugins~1~0.rc3.6.18.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xine1", rpm:"lib64xine1~1~0.rc3.6.18.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xine1-devel", rpm:"lib64xine1-devel~1~0.rc3.6.18.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
