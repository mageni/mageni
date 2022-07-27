# OpenVAS Vulnerability Test
# $Id: mdksa_2009_142_1.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:142-1 (jasper)
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
tag_insight = "Multiple security vulnerabilities has been identified and fixed
in jasper:

The jpc_qcx_getcompparms function in jpc/jpc_cs.c for the JasPer
JPEG-2000 library (libjasper) before 1.900 allows remote user-assisted
attackers to cause a denial of service (crash) and possibly corrupt
the heap via malformed image files, as originally demonstrated using
imagemagick convert (CVE-2007-2721).

Multiple integer overflows in JasPer 1.900.1 might allow
context-dependent attackers to have an unknown impact via a crafted
image file, related to integer multiplication for memory allocation
(CVE-2008-3520).

The jas_stream_tmpfile function in libjasper/base/jas_stream.c in
JasPer 1.900.1 allows local users to overwrite arbitrary files via
a symlink attack on a tmp.XXXXXXXXXX temporary file (CVE-2008-3521).

Buffer overflow in the jas_stream_printf function in
libjasper/base/jas_stream.c in JasPer 1.900.1 might allow
context-dependent attackers to have an unknown impact via
vectors related to the mif_hdr_put function and use of vsprintf
(CVE-2008-3522).

The updated packages have been patched to prevent this.

Update:

Packages for 2008.0 are being provided due to extended support for
Corporate products.

Affected: 2008.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:142-1";
tag_summary = "The remote host is missing an update to jasper
announced via advisory MDVSA-2009:142-1.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311998");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
 script_cve_id("CVE-2007-2721", "CVE-2008-3520", "CVE-2008-3521", "CVE-2008-3522");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Mandriva Security Advisory MDVSA-2009:142-1 (jasper)");



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
if ((res = isrpmvuln(pkg:"jasper", rpm:"jasper~1.900.1~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libjasper1", rpm:"libjasper1~1.900.1~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libjasper1-devel", rpm:"libjasper1-devel~1.900.1~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libjasper1-static-devel", rpm:"libjasper1-static-devel~1.900.1~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64jasper1", rpm:"lib64jasper1~1.900.1~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64jasper1-devel", rpm:"lib64jasper1-devel~1.900.1~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64jasper1-static-devel", rpm:"lib64jasper1-static-devel~1.900.1~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
