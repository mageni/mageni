# OpenVAS Vulnerability Test
# $Id: mdksa_2009_094.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:094 (mysql)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in mysql:

MySQL 5.0 before 5.0.66, 5.1 before 5.1.26, and 6.0 before 6.0.6
does not properly handle a b'' (b single-quote single-quote) token,
aka an empty bit-string literal, which allows remote attackers to
cause a denial of service (daemon crash) by using this token in a
SQL statement (CVE-2008-3963).

MySQL 5.0.51a allows local users to bypass certain privilege checks by
calling CREATE TABLE on a MyISAM table with modified (1) DATA DIRECTORY
or (2) INDEX DIRECTORY arguments that are associated with symlinks
within pathnames for subdirectories of the MySQL home data directory,
which are followed when tables are created in the future. NOTE: this
vulnerability exists because of an incomplete fix for CVE-2008-2079
(CVE-2008-4097).

MySQL before 5.0.67 allows local users to bypass certain privilege
checks by calling CREATE TABLE on a MyISAM table with modified (1)
DATA DIRECTORY or (2) INDEX DIRECTORY arguments that are originally
associated with pathnames without symlinks, and that can point to
tables created at a future time at which a pathname is modified
to contain a symlink to a subdirectory of the MySQL home data
directory. NOTE: this vulnerability exists because of an incomplete
fix for CVE-2008-4097 (CVE-2008-4098).

Cross-site scripting (XSS) vulnerability in the command-line client
in MySQL 5.0.26 through 5.0.45, when the --html option is enabled,
allows attackers to inject arbitrary web script or HTML by placing
it in a database cell, which might be accessed by this client when
composing an HTML document (CVE-2008-4456).

bugs in the Mandriva Linux 2008.1 packages that has been fixed:

o upstream fix for mysql bug35754 (#38398, #44691)
o fix #46116 (initialization file mysqld-max don't show correct
application status)
o fix upstream bug 42366

bugs in the Mandriva Linux 2009.0 packages that has been fixed:

o upgraded 5.0.67 to 5.0.77 (fixes CVE-2008-3963, CVE-2008-4097,
CVE-2008-4098)
o no need to workaround #38398, #44691 anymore (since 5.0.75)
o fix upstream bug 42366
o fix #46116 (initialization file mysqld-max don't show correct
application status)
o sphinx-0.9.8.1

bugs in the Mandriva Linux Corporate Server 4 packages that has
been fixed:
o fix upstream bug 42366
o fix #46116 (initialization file mysqld-max don't show correct
application status)

The updated packages have been patched to correct these issues.

Affected: 2008.1, 2009.0, Corporate 4.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:094";
tag_summary = "The remote host is missing an update to mysql
announced via advisory MDVSA-2009:094.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310363");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-04-28 20:40:12 +0200 (Tue, 28 Apr 2009)");
 script_cve_id("CVE-2008-3963", "CVE-2008-2079", "CVE-2008-4097", "CVE-2008-4098", "CVE-2008-4456");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
 script_name("Mandrake Security Advisory MDVSA-2009:094 (mysql)");



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
if ((res = isrpmvuln(pkg:"libmysql15", rpm:"libmysql15~5.0.51a~8.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmysql-devel", rpm:"libmysql-devel~5.0.51a~8.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmysql-static-devel", rpm:"libmysql-static-devel~5.0.51a~8.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.51a~8.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.51a~8.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-client", rpm:"mysql-client~5.0.51a~8.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-common", rpm:"mysql-common~5.0.51a~8.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-doc", rpm:"mysql-doc~5.0.51a~8.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-max", rpm:"mysql-max~5.0.51a~8.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-ndb-extra", rpm:"mysql-ndb-extra~5.0.51a~8.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-ndb-management", rpm:"mysql-ndb-management~5.0.51a~8.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-ndb-storage", rpm:"mysql-ndb-storage~5.0.51a~8.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-ndb-tools", rpm:"mysql-ndb-tools~5.0.51a~8.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mysql15", rpm:"lib64mysql15~5.0.51a~8.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mysql-devel", rpm:"lib64mysql-devel~5.0.51a~8.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mysql-static-devel", rpm:"lib64mysql-static-devel~5.0.51a~8.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmysql15", rpm:"libmysql15~5.0.77~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmysql-devel", rpm:"libmysql-devel~5.0.77~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmysql-static-devel", rpm:"libmysql-static-devel~5.0.77~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.77~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.77~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-client", rpm:"mysql-client~5.0.77~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-common", rpm:"mysql-common~5.0.77~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-doc", rpm:"mysql-doc~5.0.77~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-max", rpm:"mysql-max~5.0.77~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-ndb-extra", rpm:"mysql-ndb-extra~5.0.77~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-ndb-management", rpm:"mysql-ndb-management~5.0.77~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-ndb-storage", rpm:"mysql-ndb-storage~5.0.77~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-ndb-tools", rpm:"mysql-ndb-tools~5.0.77~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mysql15", rpm:"lib64mysql15~5.0.77~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mysql-devel", rpm:"lib64mysql-devel~5.0.77~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mysql-static-devel", rpm:"lib64mysql-static-devel~5.0.77~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmysql15", rpm:"libmysql15~5.0.45~7.3.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmysql-devel", rpm:"libmysql-devel~5.0.45~7.3.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmysql-static-devel", rpm:"libmysql-static-devel~5.0.45~7.3.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.45~7.3.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.45~7.3.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-client", rpm:"mysql-client~5.0.45~7.3.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-common", rpm:"mysql-common~5.0.45~7.3.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-max", rpm:"mysql-max~5.0.45~7.3.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-ndb-extra", rpm:"mysql-ndb-extra~5.0.45~7.3.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-ndb-management", rpm:"mysql-ndb-management~5.0.45~7.3.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-ndb-storage", rpm:"mysql-ndb-storage~5.0.45~7.3.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-ndb-tools", rpm:"mysql-ndb-tools~5.0.45~7.3.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mysql15", rpm:"lib64mysql15~5.0.45~7.3.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mysql-devel", rpm:"lib64mysql-devel~5.0.45~7.3.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mysql-static-devel", rpm:"lib64mysql-static-devel~5.0.45~7.3.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
