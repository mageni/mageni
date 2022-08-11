# OpenVAS Vulnerability Test
# $Id: mdksa_2009_225.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:225 (qt4)
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
tag_insight = "A vulnerability has been found and corrected in qt4:

src/network/ssl/qsslcertificate.cpp in Nokia Trolltech Qt 4.x
does not properly handle a '\0' character in a domain name in the
Subject Alternative Name field of an X.509 certificate, which allows
man-in-the-middle attackers to spoof arbitrary SSL servers via a
crafted certificate issued by a legitimate Certification Authority,
a related issue to CVE-2009-2408 (CVE-2009-2700).

This update provides a solution to this vulnerability.

Affected: 2009.0, 2009.1, Enterprise Server 5.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:225";
tag_summary = "The remote host is missing an update to qt4
announced via advisory MDVSA-2009:225.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306348");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-09-15 22:46:32 +0200 (Tue, 15 Sep 2009)");
 script_cve_id("CVE-2009-2408", "CVE-2009-2700");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Mandrake Security Advisory MDVSA-2009:225 (qt4)");



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
if ((res = isrpmvuln(pkg:"libqassistant4", rpm:"libqassistant4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqt3support4", rpm:"libqt3support4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqt4-devel", rpm:"libqt4-devel~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtclucene4", rpm:"libqtclucene4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtcore4", rpm:"libqtcore4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtdbus4", rpm:"libqtdbus4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtdesigner4", rpm:"libqtdesigner4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtgui4", rpm:"libqtgui4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqthelp4", rpm:"libqthelp4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtnetwork4", rpm:"libqtnetwork4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtopengl4", rpm:"libqtopengl4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtscript4", rpm:"libqtscript4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtscripttools4", rpm:"libqtscripttools4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtsql4", rpm:"libqtsql4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtsvg4", rpm:"libqtsvg4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqttest4", rpm:"libqttest4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtwebkit4", rpm:"libqtwebkit4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtxml4", rpm:"libqtxml4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtxmlpatterns4", rpm:"libqtxmlpatterns4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-accessibility-plugin", rpm:"qt4-accessibility-plugin~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-assistant", rpm:"qt4-assistant~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-common", rpm:"qt4-common~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-database-plugin-mysql", rpm:"qt4-database-plugin-mysql~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-database-plugin-odbc", rpm:"qt4-database-plugin-odbc~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-database-plugin-pgsql", rpm:"qt4-database-plugin-pgsql~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-database-plugin-sqlite", rpm:"qt4-database-plugin-sqlite~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-database-plugin-tds", rpm:"qt4-database-plugin-tds~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-designer", rpm:"qt4-designer~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-doc", rpm:"qt4-doc~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-examples", rpm:"qt4-examples~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-graphicssystems-plugin", rpm:"qt4-graphicssystems-plugin~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-linguist", rpm:"qt4-linguist~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-qdoc3", rpm:"qt4-qdoc3~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-qtconfig", rpm:"qt4-qtconfig~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-qtdbus", rpm:"qt4-qtdbus~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-qvfb", rpm:"qt4-qvfb~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-xmlpatterns", rpm:"qt4-xmlpatterns~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qassistant4", rpm:"lib64qassistant4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qt3support4", rpm:"lib64qt3support4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qt4-devel", rpm:"lib64qt4-devel~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtclucene4", rpm:"lib64qtclucene4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtcore4", rpm:"lib64qtcore4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtdbus4", rpm:"lib64qtdbus4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtdesigner4", rpm:"lib64qtdesigner4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtgui4", rpm:"lib64qtgui4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qthelp4", rpm:"lib64qthelp4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtnetwork4", rpm:"lib64qtnetwork4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtopengl4", rpm:"lib64qtopengl4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtscript4", rpm:"lib64qtscript4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtscripttools4", rpm:"lib64qtscripttools4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtsql4", rpm:"lib64qtsql4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtsvg4", rpm:"lib64qtsvg4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qttest4", rpm:"lib64qttest4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtwebkit4", rpm:"lib64qtwebkit4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtxml4", rpm:"lib64qtxml4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtxmlpatterns4", rpm:"lib64qtxmlpatterns4~4.5.2~1.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqassistant4", rpm:"libqassistant4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqt3support4", rpm:"libqt3support4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqt4-devel", rpm:"libqt4-devel~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtclucene4", rpm:"libqtclucene4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtcore4", rpm:"libqtcore4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtdbus4", rpm:"libqtdbus4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtdesigner4", rpm:"libqtdesigner4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtgui4", rpm:"libqtgui4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqthelp4", rpm:"libqthelp4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtnetwork4", rpm:"libqtnetwork4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtopengl4", rpm:"libqtopengl4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtscript4", rpm:"libqtscript4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtscripttools4", rpm:"libqtscripttools4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtsql4", rpm:"libqtsql4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtsvg4", rpm:"libqtsvg4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqttest4", rpm:"libqttest4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtwebkit4", rpm:"libqtwebkit4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtxml4", rpm:"libqtxml4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtxmlpatterns4", rpm:"libqtxmlpatterns4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-accessibility-plugin", rpm:"qt4-accessibility-plugin~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-assistant", rpm:"qt4-assistant~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-common", rpm:"qt4-common~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-database-plugin-mysql", rpm:"qt4-database-plugin-mysql~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-database-plugin-odbc", rpm:"qt4-database-plugin-odbc~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-database-plugin-pgsql", rpm:"qt4-database-plugin-pgsql~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-database-plugin-sqlite", rpm:"qt4-database-plugin-sqlite~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-database-plugin-tds", rpm:"qt4-database-plugin-tds~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-designer", rpm:"qt4-designer~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-doc", rpm:"qt4-doc~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-examples", rpm:"qt4-examples~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-graphicssystems-plugin", rpm:"qt4-graphicssystems-plugin~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-linguist", rpm:"qt4-linguist~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-qdoc3", rpm:"qt4-qdoc3~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-qtconfig", rpm:"qt4-qtconfig~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-qtdbus", rpm:"qt4-qtdbus~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-qvfb", rpm:"qt4-qvfb~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-xmlpatterns", rpm:"qt4-xmlpatterns~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qassistant4", rpm:"lib64qassistant4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qt3support4", rpm:"lib64qt3support4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qt4-devel", rpm:"lib64qt4-devel~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtclucene4", rpm:"lib64qtclucene4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtcore4", rpm:"lib64qtcore4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtdbus4", rpm:"lib64qtdbus4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtdesigner4", rpm:"lib64qtdesigner4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtgui4", rpm:"lib64qtgui4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qthelp4", rpm:"lib64qthelp4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtnetwork4", rpm:"lib64qtnetwork4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtopengl4", rpm:"lib64qtopengl4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtscript4", rpm:"lib64qtscript4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtscripttools4", rpm:"lib64qtscripttools4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtsql4", rpm:"lib64qtsql4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtsvg4", rpm:"lib64qtsvg4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qttest4", rpm:"lib64qttest4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtwebkit4", rpm:"lib64qtwebkit4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtxml4", rpm:"lib64qtxml4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtxmlpatterns4", rpm:"lib64qtxmlpatterns4~4.5.2~1.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqassistant4", rpm:"libqassistant4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqt3support4", rpm:"libqt3support4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqt4-devel", rpm:"libqt4-devel~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtclucene4", rpm:"libqtclucene4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtcore4", rpm:"libqtcore4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtdbus4", rpm:"libqtdbus4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtdesigner4", rpm:"libqtdesigner4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtgui4", rpm:"libqtgui4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqthelp4", rpm:"libqthelp4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtnetwork4", rpm:"libqtnetwork4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtopengl4", rpm:"libqtopengl4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtscript4", rpm:"libqtscript4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtsql4", rpm:"libqtsql4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtsvg4", rpm:"libqtsvg4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqttest4", rpm:"libqttest4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtwebkit4", rpm:"libqtwebkit4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtxml4", rpm:"libqtxml4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqtxmlpatterns4", rpm:"libqtxmlpatterns4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-accessibility-plugin-lib", rpm:"qt4-accessibility-plugin-lib~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-assistant", rpm:"qt4-assistant~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-common", rpm:"qt4-common~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-database-plugin-mysql-lib", rpm:"qt4-database-plugin-mysql-lib~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-database-plugin-odbc-lib", rpm:"qt4-database-plugin-odbc-lib~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-database-plugin-pgsql-lib", rpm:"qt4-database-plugin-pgsql-lib~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-database-plugin-sqlite-lib", rpm:"qt4-database-plugin-sqlite-lib~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-designer", rpm:"qt4-designer~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-doc", rpm:"qt4-doc~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-examples", rpm:"qt4-examples~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-linguist", rpm:"qt4-linguist~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-qtconfig", rpm:"qt4-qtconfig~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-qtdbus", rpm:"qt4-qtdbus~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-qvfb", rpm:"qt4-qvfb~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-xmlpatterns", rpm:"qt4-xmlpatterns~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qassistant4", rpm:"lib64qassistant4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qt3support4", rpm:"lib64qt3support4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qt4-devel", rpm:"lib64qt4-devel~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtclucene4", rpm:"lib64qtclucene4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtcore4", rpm:"lib64qtcore4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtdbus4", rpm:"lib64qtdbus4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtdesigner4", rpm:"lib64qtdesigner4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtgui4", rpm:"lib64qtgui4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qthelp4", rpm:"lib64qthelp4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtnetwork4", rpm:"lib64qtnetwork4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtopengl4", rpm:"lib64qtopengl4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtscript4", rpm:"lib64qtscript4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtsql4", rpm:"lib64qtsql4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtsvg4", rpm:"lib64qtsvg4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qttest4", rpm:"lib64qttest4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtwebkit4", rpm:"lib64qtwebkit4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtxml4", rpm:"lib64qtxml4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64qtxmlpatterns4", rpm:"lib64qtxmlpatterns4~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-accessibility-plugin-lib64", rpm:"qt4-accessibility-plugin-lib64~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-database-plugin-mysql-lib64", rpm:"qt4-database-plugin-mysql-lib64~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-database-plugin-odbc-lib64", rpm:"qt4-database-plugin-odbc-lib64~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-database-plugin-pgsql-lib64", rpm:"qt4-database-plugin-pgsql-lib64~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt4-database-plugin-sqlite-lib64", rpm:"qt4-database-plugin-sqlite-lib64~4.4.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
