# OpenVAS Vulnerability Test
# $Id: mdksa_2009_314.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:314 (apr)
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
apr and apr-util:

Multiple integer overflows in the Apache Portable Runtime (APR)
library and the Apache Portable Utility library (aka APR-util)
0.9.x and 1.3.x allow remote attackers to cause a denial of service
(application crash) or possibly execute arbitrary code via vectors that
trigger crafted calls to the (1) allocator_alloc or (2) apr_palloc
function in memory/unix/apr_pools.c in APR; or crafted calls to
the (3) apr_rmm_malloc, (4) apr_rmm_calloc, or (5) apr_rmm_realloc
function in misc/apr_rmm.c in APR-util; leading to buffer overflows.
NOTE: some of these details are obtained from third party information
(CVE-2009-2412).

The apr_strmatch_precompile function in strmatch/apr_strmatch.c in
Apache APR-util before 1.3.5 allows remote attackers to cause a denial
of service (daemon crash) via crafted input involving (1) a .htaccess
file used with the Apache HTTP Server, (2) the SVNMasterURI directive
in the mod_dav_svn module in the Apache HTTP Server, (3) the mod_apreq2
module for the Apache HTTP Server, or (4) an application that uses
the libapreq2 library, related to an underflow flaw. (CVE-2009-0023).

The expat XML parser in the apr_xml_* interface in xml/apr_xml.c in
Apache APR-util before 1.3.7, as used in the mod_dav and mod_dav_svn
modules in the Apache HTTP Server, allows remote attackers to
cause a denial of service (memory consumption) via a crafted XML
document containing a large number of nested entity references, as
demonstrated by a PROPFIND request, a similar issue to CVE-2003-1564
(CVE-2009-1955).

Off-by-one error in the apr_brigade_vprintf function in Apache APR-util
before 1.3.5 on big-endian platforms allows remote attackers to obtain
sensitive information or cause a denial of service (application crash)
via crafted input (CVE-2009-1956).

Packages for 2008.0 are being provided due to extended support for
Corporate products.

The updated packages have been patched to prevent this.

Affected: 2008.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:314";
tag_summary = "The remote host is missing an update to apr
announced via advisory MDVSA-2009:314.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306576");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
 script_cve_id("CVE-2009-2412", "CVE-2009-0023", "CVE-2003-1564", "CVE-2009-1955", "CVE-2009-1956");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Mandriva Security Advisory MDVSA-2009:314 (apr)");



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
if ((res = isrpmvuln(pkg:"apr-util-dbd-mysql", rpm:"apr-util-dbd-mysql~1.2.10~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-pgsql", rpm:"apr-util-dbd-pgsql~1.2.10~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-sqlite3", rpm:"apr-util-dbd-sqlite3~1.2.10~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr1", rpm:"libapr1~1.2.11~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-devel", rpm:"libapr-devel~1.2.11~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1", rpm:"libapr-util1~1.2.10~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util-devel", rpm:"libapr-util-devel~1.2.10~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64apr1", rpm:"lib64apr1~1.2.11~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64apr-devel", rpm:"lib64apr-devel~1.2.11~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64apr-util1", rpm:"lib64apr-util1~1.2.10~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64apr-util-devel", rpm:"lib64apr-util-devel~1.2.10~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
