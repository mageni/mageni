# OpenVAS Vulnerability Test
# $Id: mdksa_2009_265.nasl 6587 2017-07-07 06:35:35Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:265 (egroupware)
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
tag_insight = "A vulnerability has been found and corrected in egroupware:

The _bad_protocol_once function in phpgwapi/inc/class.kses.inc.php
in KSES, as used in eGroupWare before 1.4.003, Moodle before 1.8.5,
and other products, allows remote attackers to bypass HTML filtering
and conduct cross-site scripting (XSS) attacks via a string containing
crafted URL protocols (CVE-2008-1502).

This update fixes this vulnerability.

Affected: Corporate 3.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:265";
tag_summary = "The remote host is missing an update to egroupware
announced via advisory MDVSA-2009:265.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306694");
 script_version("$Revision: 6587 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 08:35:35 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-19 21:50:22 +0200 (Mon, 19 Oct 2009)");
 script_cve_id("CVE-2008-1502");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Mandrake Security Advisory MDVSA-2009:265 (egroupware)");



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
if ((res = isrpmvuln(pkg:"egroupware", rpm:"egroupware~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-addressbook", rpm:"egroupware-addressbook~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-backup", rpm:"egroupware-backup~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-bookmarks", rpm:"egroupware-bookmarks~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-calendar", rpm:"egroupware-calendar~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-comic", rpm:"egroupware-comic~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-developer_tools", rpm:"egroupware-developer_tools~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-email", rpm:"egroupware-email~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-emailadmin", rpm:"egroupware-emailadmin~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-etemplate", rpm:"egroupware-etemplate~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-felamimail", rpm:"egroupware-felamimail~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-filemanager", rpm:"egroupware-filemanager~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-forum", rpm:"egroupware-forum~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-ftp", rpm:"egroupware-ftp~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-fudforum", rpm:"egroupware-fudforum~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-headlines", rpm:"egroupware-headlines~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-infolog", rpm:"egroupware-infolog~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-jinn", rpm:"egroupware-jinn~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-messenger", rpm:"egroupware-messenger~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-news_admin", rpm:"egroupware-news_admin~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-phpbrain", rpm:"egroupware-phpbrain~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-phpldapadmin", rpm:"egroupware-phpldapadmin~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-phpsysinfo", rpm:"egroupware-phpsysinfo~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-polls", rpm:"egroupware-polls~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-projects", rpm:"egroupware-projects~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-registration", rpm:"egroupware-registration~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-sitemgr", rpm:"egroupware-sitemgr~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-skel", rpm:"egroupware-skel~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-stocks", rpm:"egroupware-stocks~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-tts", rpm:"egroupware-tts~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-wiki", rpm:"egroupware-wiki~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
