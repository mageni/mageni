# OpenVAS Vulnerability Test
# $Id: mdksa_2009_222.nasl 6587 2017-07-07 06:35:35Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:222 (squirrelmail)
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
tag_insight = "A vulnerability has been found and corrected in squirrelmail:

All form submissions (send message, change preferences, etc.) in
SquirrelMail were previously subject to cross-site request forgery
(CSRF), wherein data could be sent to them from an offsite location,
which could allow an attacker to inject malicious content into
user preferences or possibly send emails without user consent
(CVE-2009-2964).

This update provides a solution to this vulnerability.

Affected: Corporate 4.0, Enterprise Server 5.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:222";
tag_summary = "The remote host is missing an update to squirrelmail
announced via advisory MDVSA-2009:222.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310206");
 script_version("$Revision: 6587 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 08:35:35 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
 script_cve_id("CVE-2009-2964");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Mandrake Security Advisory MDVSA-2009:222 (squirrelmail)");



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
if ((res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-ar", rpm:"squirrelmail-ar~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-bg", rpm:"squirrelmail-bg~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-bn", rpm:"squirrelmail-bn~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-ca", rpm:"squirrelmail-ca~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-cs", rpm:"squirrelmail-cs~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-cy", rpm:"squirrelmail-cy~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-cyrus", rpm:"squirrelmail-cyrus~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-da", rpm:"squirrelmail-da~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-de", rpm:"squirrelmail-de~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-el", rpm:"squirrelmail-el~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-en", rpm:"squirrelmail-en~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-es", rpm:"squirrelmail-es~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-et", rpm:"squirrelmail-et~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-eu", rpm:"squirrelmail-eu~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-fa", rpm:"squirrelmail-fa~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-fi", rpm:"squirrelmail-fi~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-fo", rpm:"squirrelmail-fo~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-fr", rpm:"squirrelmail-fr~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-fy", rpm:"squirrelmail-fy~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-he", rpm:"squirrelmail-he~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-hr", rpm:"squirrelmail-hr~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-hu", rpm:"squirrelmail-hu~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-id", rpm:"squirrelmail-id~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-is", rpm:"squirrelmail-is~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-it", rpm:"squirrelmail-it~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-ja", rpm:"squirrelmail-ja~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-ka", rpm:"squirrelmail-ka~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-ko", rpm:"squirrelmail-ko~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-lt", rpm:"squirrelmail-lt~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-ms", rpm:"squirrelmail-ms~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-nb", rpm:"squirrelmail-nb~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-nl", rpm:"squirrelmail-nl~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-nn", rpm:"squirrelmail-nn~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-pl", rpm:"squirrelmail-pl~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-poutils", rpm:"squirrelmail-poutils~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-pt", rpm:"squirrelmail-pt~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-ro", rpm:"squirrelmail-ro~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-ru", rpm:"squirrelmail-ru~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-sk", rpm:"squirrelmail-sk~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-sl", rpm:"squirrelmail-sl~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-sr", rpm:"squirrelmail-sr~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-sv", rpm:"squirrelmail-sv~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-th", rpm:"squirrelmail-th~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-tr", rpm:"squirrelmail-tr~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-ug", rpm:"squirrelmail-ug~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-uk", rpm:"squirrelmail-uk~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-vi", rpm:"squirrelmail-vi~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-zh_CN", rpm:"squirrelmail-zh_CN~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-zh_TW", rpm:"squirrelmail-zh_TW~1.4.19~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-ar", rpm:"squirrelmail-ar~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-bg", rpm:"squirrelmail-bg~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-bn", rpm:"squirrelmail-bn~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-ca", rpm:"squirrelmail-ca~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-cs", rpm:"squirrelmail-cs~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-cy", rpm:"squirrelmail-cy~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-cyrus", rpm:"squirrelmail-cyrus~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-da", rpm:"squirrelmail-da~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-de", rpm:"squirrelmail-de~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-el", rpm:"squirrelmail-el~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-en", rpm:"squirrelmail-en~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-es", rpm:"squirrelmail-es~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-et", rpm:"squirrelmail-et~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-eu", rpm:"squirrelmail-eu~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-fa", rpm:"squirrelmail-fa~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-fi", rpm:"squirrelmail-fi~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-fo", rpm:"squirrelmail-fo~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-fr", rpm:"squirrelmail-fr~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-fy", rpm:"squirrelmail-fy~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-he", rpm:"squirrelmail-he~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-hr", rpm:"squirrelmail-hr~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-hu", rpm:"squirrelmail-hu~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-id", rpm:"squirrelmail-id~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-is", rpm:"squirrelmail-is~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-it", rpm:"squirrelmail-it~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-ja", rpm:"squirrelmail-ja~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-ka", rpm:"squirrelmail-ka~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-ko", rpm:"squirrelmail-ko~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-lt", rpm:"squirrelmail-lt~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-ms", rpm:"squirrelmail-ms~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-nb", rpm:"squirrelmail-nb~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-nl", rpm:"squirrelmail-nl~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-nn", rpm:"squirrelmail-nn~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-pl", rpm:"squirrelmail-pl~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-poutils", rpm:"squirrelmail-poutils~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-pt", rpm:"squirrelmail-pt~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-ro", rpm:"squirrelmail-ro~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-ru", rpm:"squirrelmail-ru~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-sk", rpm:"squirrelmail-sk~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-sl", rpm:"squirrelmail-sl~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-sr", rpm:"squirrelmail-sr~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-sv", rpm:"squirrelmail-sv~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-th", rpm:"squirrelmail-th~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-tr", rpm:"squirrelmail-tr~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-ug", rpm:"squirrelmail-ug~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-uk", rpm:"squirrelmail-uk~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-vi", rpm:"squirrelmail-vi~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-zh_CN", rpm:"squirrelmail-zh_CN~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail-zh_TW", rpm:"squirrelmail-zh_TW~1.4.19~2.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
