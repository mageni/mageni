# OpenVAS Vulnerability Test
# $Id: mdksa_2009_017.nasl 6587 2017-07-07 06:35:35Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:017 (kdebase)
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
tag_insight = "A vulnerability in KDM allowed a local user to cause a denial of
service via unknown vectors (CVE-2007-5963).

The updated packages have been patched to prevent this issue.

Affected: Corporate 3.0, Corporate 4.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:017";
tag_summary = "The remote host is missing an update to kdebase
announced via advisory MDVSA-2009:017.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311922");
 script_version("$Revision: 6587 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 08:35:35 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-01-20 22:42:09 +0100 (Tue, 20 Jan 2009)");
 script_cve_id("CVE-2007-5963");
 script_tag(name:"cvss_base", value:"4.7");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
 script_name("Mandrake Security Advisory MDVSA-2009:017 (kdebase)");



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
if ((res = isrpmvuln(pkg:"kdebase", rpm:"kdebase~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-common", rpm:"kdebase-common~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kate", rpm:"kdebase-kate~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kcontrol-data", rpm:"kdebase-kcontrol-data~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kdeprintfax", rpm:"kdebase-kdeprintfax~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kdm", rpm:"kdebase-kdm~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kdm-config-file", rpm:"kdebase-kdm-config-file~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kmenuedit", rpm:"kdebase-kmenuedit~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-konsole", rpm:"kdebase-konsole~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-nsplugins", rpm:"kdebase-nsplugins~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-progs", rpm:"kdebase-progs~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4", rpm:"libkdebase4~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-devel", rpm:"libkdebase4-devel~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-kate", rpm:"libkdebase4-kate~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-kate-devel", rpm:"libkdebase4-kate-devel~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-kmenuedit", rpm:"libkdebase4-kmenuedit~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-konsole", rpm:"libkdebase4-konsole~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-nsplugins", rpm:"libkdebase4-nsplugins~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-nsplugins-devel", rpm:"libkdebase4-nsplugins-devel~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4", rpm:"lib64kdebase4~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-devel", rpm:"lib64kdebase4-devel~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-kate", rpm:"lib64kdebase4-kate~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-kate-devel", rpm:"lib64kdebase4-kate-devel~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-kmenuedit", rpm:"lib64kdebase4-kmenuedit~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-konsole", rpm:"lib64kdebase4-konsole~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-nsplugins", rpm:"lib64kdebase4-nsplugins~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-nsplugins-devel", rpm:"lib64kdebase4-nsplugins-devel~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase", rpm:"kdebase~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-common", rpm:"kdebase-common~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-common-doc", rpm:"kdebase-common-doc~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kate", rpm:"kdebase-kate~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kcontrol-data", rpm:"kdebase-kcontrol-data~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kcontrol-doc", rpm:"kdebase-kcontrol-doc~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kdeprintfax", rpm:"kdebase-kdeprintfax~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kdm", rpm:"kdebase-kdm~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kmenuedit", rpm:"kdebase-kmenuedit~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-konsole", rpm:"kdebase-konsole~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-nsplugins", rpm:"kdebase-nsplugins~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-progs", rpm:"kdebase-progs~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkateinterfaces0", rpm:"libkateinterfaces0~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkateutils0", rpm:"libkateutils0~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4", rpm:"libkdebase4~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-devel", rpm:"libkdebase4-devel~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-devel-doc", rpm:"libkdebase4-devel-doc~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-kate", rpm:"libkdebase4-kate~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kateinterfaces0", rpm:"lib64kateinterfaces0~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kateutils0", rpm:"lib64kateutils0~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4", rpm:"lib64kdebase4~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-devel", rpm:"lib64kdebase4-devel~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-devel-doc", rpm:"lib64kdebase4-devel-doc~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-kate", rpm:"lib64kdebase4-kate~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
