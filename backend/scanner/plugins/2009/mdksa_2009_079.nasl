# OpenVAS Vulnerability Test
# $Id: mdksa_2009_079.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:079 (postgresql)
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
tag_insight = "PostgreSQL before 8.3.7, 8.2.13, 8.1.17, 8.0.21, and 7.4.25 allows
remote authenticated users to cause a denial of service (stack
consumption and crash) by triggering a failure in the conversion of a
localized error message to a client-specified encoding, as demonstrated
using mismatched encoding conversion requests (CVE-2009-0922).

This update provides a fix for this vulnerability.

Affected: 2008.0, 2008.1, 2009.0, Corporate 3.0, Corporate 4.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:079";
tag_summary = "The remote host is missing an update to postgresql
announced via advisory MDVSA-2009:079.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309091");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
 script_cve_id("CVE-2009-0922");
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
 script_name("Mandrake Security Advisory MDVSA-2009:079 (postgresql)");



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
if ((res = isrpmvuln(pkg:"libecpg5", rpm:"libecpg5~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libecpg-devel", rpm:"libecpg-devel~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpq-devel", rpm:"libpq-devel~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2", rpm:"postgresql8.2~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-contrib", rpm:"postgresql8.2-contrib~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-devel", rpm:"postgresql8.2-devel~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-docs", rpm:"postgresql8.2-docs~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-pl", rpm:"postgresql8.2-pl~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-plperl", rpm:"postgresql8.2-plperl~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-plpgsql", rpm:"postgresql8.2-plpgsql~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-plpython", rpm:"postgresql8.2-plpython~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-pltcl", rpm:"postgresql8.2-pltcl~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-server", rpm:"postgresql8.2-server~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-test", rpm:"postgresql8.2-test~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ecpg5", rpm:"lib64ecpg5~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ecpg-devel", rpm:"lib64ecpg-devel~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pq5", rpm:"lib64pq5~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pq-devel", rpm:"lib64pq-devel~8.2.13~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libecpg8.3_6", rpm:"libecpg8.3_6~8.3.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpq8.3_5", rpm:"libpq8.3_5~8.3.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3", rpm:"postgresql8.3~8.3.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3-contrib", rpm:"postgresql8.3-contrib~8.3.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3-devel", rpm:"postgresql8.3-devel~8.3.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3-docs", rpm:"postgresql8.3-docs~8.3.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3-pl", rpm:"postgresql8.3-pl~8.3.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3-plperl", rpm:"postgresql8.3-plperl~8.3.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3-plpgsql", rpm:"postgresql8.3-plpgsql~8.3.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3-plpython", rpm:"postgresql8.3-plpython~8.3.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3-pltcl", rpm:"postgresql8.3-pltcl~8.3.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3-server", rpm:"postgresql8.3-server~8.3.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ecpg8.3_6", rpm:"lib64ecpg8.3_6~8.3.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pq8.3_5", rpm:"lib64pq8.3_5~8.3.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libecpg8.3_6", rpm:"libecpg8.3_6~8.3.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpq8.3_5", rpm:"libpq8.3_5~8.3.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3", rpm:"postgresql8.3~8.3.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3-contrib", rpm:"postgresql8.3-contrib~8.3.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3-devel", rpm:"postgresql8.3-devel~8.3.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3-docs", rpm:"postgresql8.3-docs~8.3.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3-pl", rpm:"postgresql8.3-pl~8.3.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3-plperl", rpm:"postgresql8.3-plperl~8.3.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3-plpgsql", rpm:"postgresql8.3-plpgsql~8.3.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3-plpython", rpm:"postgresql8.3-plpython~8.3.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3-pltcl", rpm:"postgresql8.3-pltcl~8.3.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.3-server", rpm:"postgresql8.3-server~8.3.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ecpg8.3_6", rpm:"lib64ecpg8.3_6~8.3.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pq8.3_5", rpm:"lib64pq8.3_5~8.3.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libecpg3", rpm:"libecpg3~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libecpg3-devel", rpm:"libecpg3-devel~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpgtcl2", rpm:"libpgtcl2~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpgtcl2-devel", rpm:"libpgtcl2-devel~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpq3", rpm:"libpq3~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpq3-devel", rpm:"libpq3-devel~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-jdbc", rpm:"postgresql-jdbc~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-pl", rpm:"postgresql-pl~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-tcl", rpm:"postgresql-tcl~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ecpg3", rpm:"lib64ecpg3~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ecpg3-devel", rpm:"lib64ecpg3-devel~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pgtcl2", rpm:"lib64pgtcl2~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pgtcl2-devel", rpm:"lib64pgtcl2-devel~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pq3", rpm:"lib64pq3~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pq3-devel", rpm:"lib64pq3-devel~7.4.25~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libecpg5", rpm:"libecpg5~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libecpg5-devel", rpm:"libecpg5-devel~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpq4", rpm:"libpq4~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpq4-devel", rpm:"libpq4-devel~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-pl", rpm:"postgresql-pl~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-plperl", rpm:"postgresql-plperl~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-plpgsql", rpm:"postgresql-plpgsql~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-plpython", rpm:"postgresql-plpython~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-pltcl", rpm:"postgresql-pltcl~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ecpg5", rpm:"lib64ecpg5~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ecpg5-devel", rpm:"lib64ecpg5-devel~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pq4", rpm:"lib64pq4~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pq4-devel", rpm:"lib64pq4-devel~8.1.17~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
