# OpenVAS Vulnerability Test
# $Id: mdksa_2009_131.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:131 (apr-util)
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
in apr-util:

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

The updated packages have been patched to prevent this.

Affected: 2008.1, 2009.0, 2009.1, Corporate 4.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:131";
tag_summary = "The remote host is missing an update to apr-util
announced via advisory MDVSA-2009:131.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306100");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-06-09 19:38:29 +0200 (Tue, 09 Jun 2009)");
 script_cve_id("CVE-2009-0023", "CVE-2003-1564", "CVE-2009-1955", "CVE-2009-1956");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Mandrake Security Advisory MDVSA-2009:131 (apr-util)");



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
if ((res = isrpmvuln(pkg:"apr-util-dbd-mysql", rpm:"apr-util-dbd-mysql~1.2.12~4.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-pgsql", rpm:"apr-util-dbd-pgsql~1.2.12~4.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-sqlite3", rpm:"apr-util-dbd-sqlite3~1.2.12~4.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1", rpm:"libapr-util1~1.2.12~4.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util-devel", rpm:"libapr-util-devel~1.2.12~4.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64apr-util1", rpm:"lib64apr-util1~1.2.12~4.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64apr-util-devel", rpm:"lib64apr-util-devel~1.2.12~4.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-freetds", rpm:"apr-util-dbd-freetds~1.3.4~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-ldap", rpm:"apr-util-dbd-ldap~1.3.4~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-mysql", rpm:"apr-util-dbd-mysql~1.3.4~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-odbc", rpm:"apr-util-dbd-odbc~1.3.4~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-pgsql", rpm:"apr-util-dbd-pgsql~1.3.4~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-sqlite3", rpm:"apr-util-dbd-sqlite3~1.3.4~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1", rpm:"libapr-util1~1.3.4~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util-devel", rpm:"libapr-util-devel~1.3.4~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64apr-util1", rpm:"lib64apr-util1~1.3.4~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64apr-util-devel", rpm:"lib64apr-util-devel~1.3.4~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-freetds", rpm:"apr-util-dbd-freetds~1.3.4~9.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-ldap", rpm:"apr-util-dbd-ldap~1.3.4~9.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-mysql", rpm:"apr-util-dbd-mysql~1.3.4~9.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-odbc", rpm:"apr-util-dbd-odbc~1.3.4~9.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-pgsql", rpm:"apr-util-dbd-pgsql~1.3.4~9.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-sqlite3", rpm:"apr-util-dbd-sqlite3~1.3.4~9.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1", rpm:"libapr-util1~1.3.4~9.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util-devel", rpm:"libapr-util-devel~1.3.4~9.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64apr-util1", rpm:"lib64apr-util1~1.3.4~9.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64apr-util-devel", rpm:"lib64apr-util-devel~1.3.4~9.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-mysql", rpm:"apr-util-dbd-mysql~1.2.7~6.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-pgsql", rpm:"apr-util-dbd-pgsql~1.2.7~6.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apr-util-dbd-sqlite3", rpm:"apr-util-dbd-sqlite3~1.2.7~6.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1", rpm:"libapr-util1~1.2.7~6.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-devel", rpm:"libapr-util1-devel~1.2.7~6.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64apr-util1", rpm:"lib64apr-util1~1.2.7~6.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64apr-util1-devel", rpm:"lib64apr-util1-devel~1.2.7~6.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
