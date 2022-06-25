# OpenVAS Vulnerability Test
# $Id: mdksa_2009_083.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:083 (mozilla-thunderbird)
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
tag_insight = "A number of security vulnerabilities have been discovered in previous
versions, and corrected in the latest Mozilla Thunderbird program,
version 2.0.0.21 (CVE-2009-0040, CVE-2009-0776, CVE-2009-0771,
CVE-2009-0772, CVE-2009-0773, CVE-2009-0774, CVE-2009-0352,
CVE-2009-0353).

This update provides the latest Thunderbird to correct these issues.

Additionally, Mozilla Thunderbird released with Mandriva Linux 2009.0,
when used with Enigmail extension on x86_64 architecture, would freeze
whenever any Enigmail function was used (bug #45001). Also, when used
on i586 architecture, Thunderbird would crash when sending an email,
if a file with an unknown extension was attached to it. (bug #46107)

This update also fixes those issues.

Affected: 2008.1, 2009.0, Corporate 3.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:083
http://www.mozilla.org/security/known-vulnerabilities/thunderbird20.html#thunderbird2.0.0.21";
tag_summary = "The remote host is missing an update to mozilla-thunderbird
announced via advisory MDVSA-2009:083.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308762");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-04-06 20:58:11 +0200 (Mon, 06 Apr 2009)");
 script_cve_id("CVE-2009-0040", "CVE-2009-0776", "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0352", "CVE-2009-0353");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Mandrake Security Advisory MDVSA-2009:083 (mozilla-thunderbird)");



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
if ((res = isrpmvuln(pkg:"beagle", rpm:"beagle~0.3.3~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-crawl-system", rpm:"beagle-crawl-system~0.3.3~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-doc", rpm:"beagle-doc~0.3.3~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-epiphany", rpm:"beagle-epiphany~0.3.3~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-evolution", rpm:"beagle-evolution~0.3.3~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-gui", rpm:"beagle-gui~0.3.3~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-firefox-ext-beagle", rpm:"mozilla-firefox-ext-beagle~0.3.3~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird", rpm:"mozilla-thunderbird~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-af", rpm:"mozilla-thunderbird-af~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-be", rpm:"mozilla-thunderbird-be~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-beagle", rpm:"mozilla-thunderbird-beagle~0.3.3~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-bg", rpm:"mozilla-thunderbird-bg~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ca", rpm:"mozilla-thunderbird-ca~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-cs", rpm:"mozilla-thunderbird-cs~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-da", rpm:"mozilla-thunderbird-da~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-de", rpm:"mozilla-thunderbird-de~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-devel", rpm:"mozilla-thunderbird-devel~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-el", rpm:"mozilla-thunderbird-el~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-en_GB", rpm:"mozilla-thunderbird-en_GB~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail", rpm:"mozilla-thunderbird-enigmail~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ar", rpm:"mozilla-thunderbird-enigmail-ar~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ca", rpm:"mozilla-thunderbird-enigmail-ca~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-cs", rpm:"mozilla-thunderbird-enigmail-cs~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-de", rpm:"mozilla-thunderbird-enigmail-de~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-el", rpm:"mozilla-thunderbird-enigmail-el~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-es", rpm:"mozilla-thunderbird-enigmail-es~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-es_AR", rpm:"mozilla-thunderbird-enigmail-es_AR~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fi", rpm:"mozilla-thunderbird-enigmail-fi~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fr", rpm:"mozilla-thunderbird-enigmail-fr~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-hu", rpm:"mozilla-thunderbird-enigmail-hu~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-it", rpm:"mozilla-thunderbird-enigmail-it~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ja", rpm:"mozilla-thunderbird-enigmail-ja~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ko", rpm:"mozilla-thunderbird-enigmail-ko~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nb", rpm:"mozilla-thunderbird-enigmail-nb~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nl", rpm:"mozilla-thunderbird-enigmail-nl~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pl", rpm:"mozilla-thunderbird-enigmail-pl~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt", rpm:"mozilla-thunderbird-enigmail-pt~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt_BR", rpm:"mozilla-thunderbird-enigmail-pt_BR~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ro", rpm:"mozilla-thunderbird-enigmail-ro~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ru", rpm:"mozilla-thunderbird-enigmail-ru~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sk", rpm:"mozilla-thunderbird-enigmail-sk~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sl", rpm:"mozilla-thunderbird-enigmail-sl~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sv", rpm:"mozilla-thunderbird-enigmail-sv~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-tr", rpm:"mozilla-thunderbird-enigmail-tr~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_CN", rpm:"mozilla-thunderbird-enigmail-zh_CN~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_TW", rpm:"mozilla-thunderbird-enigmail-zh_TW~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-es_AR", rpm:"mozilla-thunderbird-es_AR~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-es_ES", rpm:"mozilla-thunderbird-es_ES~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-et_EE", rpm:"mozilla-thunderbird-et_EE~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-eu", rpm:"mozilla-thunderbird-eu~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fi", rpm:"mozilla-thunderbird-fi~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fr", rpm:"mozilla-thunderbird-fr~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ga", rpm:"mozilla-thunderbird-ga~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-gu_IN", rpm:"mozilla-thunderbird-gu_IN~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-he", rpm:"mozilla-thunderbird-he~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-hu", rpm:"mozilla-thunderbird-hu~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-it", rpm:"mozilla-thunderbird-it~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ja", rpm:"mozilla-thunderbird-ja~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ko", rpm:"mozilla-thunderbird-ko~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-lt", rpm:"mozilla-thunderbird-lt~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-mk", rpm:"mozilla-thunderbird-mk~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-moztraybiff", rpm:"mozilla-thunderbird-moztraybiff~1.2.3~4.5mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nb_NO", rpm:"mozilla-thunderbird-nb_NO~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nl", rpm:"mozilla-thunderbird-nl~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nn_NO", rpm:"mozilla-thunderbird-nn_NO~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pa_IN", rpm:"mozilla-thunderbird-pa_IN~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pl", rpm:"mozilla-thunderbird-pl~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pt_BR", rpm:"mozilla-thunderbird-pt_BR~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pt_PT", rpm:"mozilla-thunderbird-pt_PT~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ru", rpm:"mozilla-thunderbird-ru~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sk", rpm:"mozilla-thunderbird-sk~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sl", rpm:"mozilla-thunderbird-sl~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sv_SE", rpm:"mozilla-thunderbird-sv_SE~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-tr", rpm:"mozilla-thunderbird-tr~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-uk", rpm:"mozilla-thunderbird-uk~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-zh_CN", rpm:"mozilla-thunderbird-zh_CN~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-zh_TW", rpm:"mozilla-thunderbird-zh_TW~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nsinstall", rpm:"nsinstall~2.0.0.21~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle", rpm:"beagle~0.3.8~13.8mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-crawl-system", rpm:"beagle-crawl-system~0.3.8~13.8mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-doc", rpm:"beagle-doc~0.3.8~13.8mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-epiphany", rpm:"beagle-epiphany~0.3.8~13.8mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-evolution", rpm:"beagle-evolution~0.3.8~13.8mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-gui", rpm:"beagle-gui~0.3.8~13.8mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-gui-qt", rpm:"beagle-gui-qt~0.3.8~13.8mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-libs", rpm:"beagle-libs~0.3.8~13.8mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ext-beagle", rpm:"firefox-ext-beagle~0.3.8~13.8mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird", rpm:"mozilla-thunderbird~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-af", rpm:"mozilla-thunderbird-af~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-be", rpm:"mozilla-thunderbird-be~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-beagle", rpm:"mozilla-thunderbird-beagle~0.3.8~13.8mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-bg", rpm:"mozilla-thunderbird-bg~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ca", rpm:"mozilla-thunderbird-ca~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-cs", rpm:"mozilla-thunderbird-cs~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-da", rpm:"mozilla-thunderbird-da~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-de", rpm:"mozilla-thunderbird-de~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-devel", rpm:"mozilla-thunderbird-devel~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-el", rpm:"mozilla-thunderbird-el~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-en_GB", rpm:"mozilla-thunderbird-en_GB~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail", rpm:"mozilla-thunderbird-enigmail~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ar", rpm:"mozilla-thunderbird-enigmail-ar~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ca", rpm:"mozilla-thunderbird-enigmail-ca~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-cs", rpm:"mozilla-thunderbird-enigmail-cs~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-de", rpm:"mozilla-thunderbird-enigmail-de~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-el", rpm:"mozilla-thunderbird-enigmail-el~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-es", rpm:"mozilla-thunderbird-enigmail-es~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-es_AR", rpm:"mozilla-thunderbird-enigmail-es_AR~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fi", rpm:"mozilla-thunderbird-enigmail-fi~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fr", rpm:"mozilla-thunderbird-enigmail-fr~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-hu", rpm:"mozilla-thunderbird-enigmail-hu~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-it", rpm:"mozilla-thunderbird-enigmail-it~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ja", rpm:"mozilla-thunderbird-enigmail-ja~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ko", rpm:"mozilla-thunderbird-enigmail-ko~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nb", rpm:"mozilla-thunderbird-enigmail-nb~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nl", rpm:"mozilla-thunderbird-enigmail-nl~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pl", rpm:"mozilla-thunderbird-enigmail-pl~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt", rpm:"mozilla-thunderbird-enigmail-pt~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt_BR", rpm:"mozilla-thunderbird-enigmail-pt_BR~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ro", rpm:"mozilla-thunderbird-enigmail-ro~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ru", rpm:"mozilla-thunderbird-enigmail-ru~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sk", rpm:"mozilla-thunderbird-enigmail-sk~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sl", rpm:"mozilla-thunderbird-enigmail-sl~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sv", rpm:"mozilla-thunderbird-enigmail-sv~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-tr", rpm:"mozilla-thunderbird-enigmail-tr~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_CN", rpm:"mozilla-thunderbird-enigmail-zh_CN~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_TW", rpm:"mozilla-thunderbird-enigmail-zh_TW~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-es_AR", rpm:"mozilla-thunderbird-es_AR~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-es_ES", rpm:"mozilla-thunderbird-es_ES~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-et_EE", rpm:"mozilla-thunderbird-et_EE~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-eu", rpm:"mozilla-thunderbird-eu~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fi", rpm:"mozilla-thunderbird-fi~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fr", rpm:"mozilla-thunderbird-fr~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ga", rpm:"mozilla-thunderbird-ga~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-gu_IN", rpm:"mozilla-thunderbird-gu_IN~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-he", rpm:"mozilla-thunderbird-he~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-hu", rpm:"mozilla-thunderbird-hu~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-it", rpm:"mozilla-thunderbird-it~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ja", rpm:"mozilla-thunderbird-ja~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ko", rpm:"mozilla-thunderbird-ko~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-lt", rpm:"mozilla-thunderbird-lt~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-mk", rpm:"mozilla-thunderbird-mk~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-moztraybiff", rpm:"mozilla-thunderbird-moztraybiff~1.2.4~1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nb_NO", rpm:"mozilla-thunderbird-nb_NO~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nl", rpm:"mozilla-thunderbird-nl~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nn_NO", rpm:"mozilla-thunderbird-nn_NO~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pa_IN", rpm:"mozilla-thunderbird-pa_IN~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pl", rpm:"mozilla-thunderbird-pl~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pt_BR", rpm:"mozilla-thunderbird-pt_BR~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pt_PT", rpm:"mozilla-thunderbird-pt_PT~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ru", rpm:"mozilla-thunderbird-ru~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sk", rpm:"mozilla-thunderbird-sk~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sl", rpm:"mozilla-thunderbird-sl~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sv_SE", rpm:"mozilla-thunderbird-sv_SE~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-tr", rpm:"mozilla-thunderbird-tr~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-uk", rpm:"mozilla-thunderbird-uk~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-zh_CN", rpm:"mozilla-thunderbird-zh_CN~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-zh_TW", rpm:"mozilla-thunderbird-zh_TW~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nsinstall", rpm:"nsinstall~2.0.0.21~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird", rpm:"mozilla-thunderbird~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-af", rpm:"mozilla-thunderbird-af~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-be", rpm:"mozilla-thunderbird-be~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-bg", rpm:"mozilla-thunderbird-bg~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ca", rpm:"mozilla-thunderbird-ca~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-cs", rpm:"mozilla-thunderbird-cs~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-da", rpm:"mozilla-thunderbird-da~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-de", rpm:"mozilla-thunderbird-de~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-devel", rpm:"mozilla-thunderbird-devel~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-el", rpm:"mozilla-thunderbird-el~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-en_GB", rpm:"mozilla-thunderbird-en_GB~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail", rpm:"mozilla-thunderbird-enigmail~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ar", rpm:"mozilla-thunderbird-enigmail-ar~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ca", rpm:"mozilla-thunderbird-enigmail-ca~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-cs", rpm:"mozilla-thunderbird-enigmail-cs~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-de", rpm:"mozilla-thunderbird-enigmail-de~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-el", rpm:"mozilla-thunderbird-enigmail-el~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-es", rpm:"mozilla-thunderbird-enigmail-es~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-es_AR", rpm:"mozilla-thunderbird-enigmail-es_AR~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fi", rpm:"mozilla-thunderbird-enigmail-fi~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fr", rpm:"mozilla-thunderbird-enigmail-fr~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-hu", rpm:"mozilla-thunderbird-enigmail-hu~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-it", rpm:"mozilla-thunderbird-enigmail-it~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ja", rpm:"mozilla-thunderbird-enigmail-ja~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ko", rpm:"mozilla-thunderbird-enigmail-ko~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nb", rpm:"mozilla-thunderbird-enigmail-nb~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nl", rpm:"mozilla-thunderbird-enigmail-nl~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pl", rpm:"mozilla-thunderbird-enigmail-pl~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt", rpm:"mozilla-thunderbird-enigmail-pt~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt_BR", rpm:"mozilla-thunderbird-enigmail-pt_BR~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ro", rpm:"mozilla-thunderbird-enigmail-ro~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ru", rpm:"mozilla-thunderbird-enigmail-ru~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sk", rpm:"mozilla-thunderbird-enigmail-sk~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sl", rpm:"mozilla-thunderbird-enigmail-sl~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sv", rpm:"mozilla-thunderbird-enigmail-sv~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_CN", rpm:"mozilla-thunderbird-enigmail-zh_CN~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_TW", rpm:"mozilla-thunderbird-enigmail-zh_TW~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-es_AR", rpm:"mozilla-thunderbird-es_AR~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-es_ES", rpm:"mozilla-thunderbird-es_ES~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-et_EE", rpm:"mozilla-thunderbird-et_EE~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-eu", rpm:"mozilla-thunderbird-eu~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fi", rpm:"mozilla-thunderbird-fi~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fr", rpm:"mozilla-thunderbird-fr~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-gu_IN", rpm:"mozilla-thunderbird-gu_IN~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-he", rpm:"mozilla-thunderbird-he~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-hu", rpm:"mozilla-thunderbird-hu~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-it", rpm:"mozilla-thunderbird-it~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ja", rpm:"mozilla-thunderbird-ja~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ko", rpm:"mozilla-thunderbird-ko~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-lt", rpm:"mozilla-thunderbird-lt~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-mk", rpm:"mozilla-thunderbird-mk~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nb_NO", rpm:"mozilla-thunderbird-nb_NO~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nl", rpm:"mozilla-thunderbird-nl~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nn_NO", rpm:"mozilla-thunderbird-nn_NO~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pa_IN", rpm:"mozilla-thunderbird-pa_IN~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pl", rpm:"mozilla-thunderbird-pl~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pt_BR", rpm:"mozilla-thunderbird-pt_BR~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pt_PT", rpm:"mozilla-thunderbird-pt_PT~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ru", rpm:"mozilla-thunderbird-ru~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sk", rpm:"mozilla-thunderbird-sk~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sl", rpm:"mozilla-thunderbird-sl~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sv_SE", rpm:"mozilla-thunderbird-sv_SE~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-tr", rpm:"mozilla-thunderbird-tr~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-uk", rpm:"mozilla-thunderbird-uk~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-zh_CN", rpm:"mozilla-thunderbird-zh_CN~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-zh_TW", rpm:"mozilla-thunderbird-zh_TW~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nsinstall", rpm:"nsinstall~2.0.0.21~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
