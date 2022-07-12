# OpenVAS Vulnerability Test
# $Id: fcore_2009_3280.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-3280 (moodle)
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
tag_insight = "Moodle is a course management system (CMS) - a free, Open Source software
package designed using sound pedagogical principles, to help educators create
effective online learning communities.

Update Information:

CVE-2009-1171:  The TeX filter in Moodle 1.6 before 1.6.9+, 1.7 before 1.7.7+,
1.8  before 1.8.9, and 1.9 before 1.9.5 allows user-assisted attackers to  read
arbitrary files via an input command in a $$ sequence, which  causes LaTeX to
include the contents of the file.

Upstream bug and CVS commit:
http://tracker.moodle.org/browse/MDL-18552
http://cvs.moodle.org/moodle/filter/tex/filter.php?r1=1.18.4.4&r2=1.18.4.5


Upstream further reported that the above patch is not sufficient and following
change should be used instead:
   For >=1.9.0:  http://git.catalyst.net.nz/gw?p=moodle-r2.git;a=commitdiff;h=b950f126018a9e16a298d278375a0eedf791e5dd
   For 1.6.* - 1.8.*:  http://git.catalyst.net.nz/gw?p=moodle-r2.git;a=commitdiff;h=cc9bf1486e7ea9e8cda1e4522b96e07245459a0d

ChangeLog:

* Wed Apr  1 2009 Jon Ciesla  - 1.9.4-6
- Patch for CVE-2009-1171, BZ 493109.
* Tue Mar 24 2009 Jon Ciesla  - 1.9.4-5
- Update for freefont->gnu-free-fonts change.";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update moodle' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3280";
tag_summary = "The remote host is missing an update to moodle
announced via advisory FEDORA-2009-3280.";



if(description)
{
script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/502231/100/0/threaded");
script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34278");
script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8297");
 script_oid("1.3.6.1.4.1.25623.1.0.308849");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-04-06 20:58:11 +0200 (Mon, 06 Apr 2009)");
 script_cve_id("CVE-2009-1171", "CVE-2009-0499", "CVE-2008-5153", "CVE-2008-4796");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Fedora Core 10 FEDORA-2009-3280 (moodle)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Fedora Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
script_tag(name : "insight" , value : tag_insight);
script_tag(name : "solution" , value : tag_solution);
script_tag(name : "summary" , value : tag_summary);
script_tag(name:"qod_type", value:"package");
script_tag(name:"solution_type", value:"VendorFix");
script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=493109");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"moodle", rpm:"moodle~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-af", rpm:"moodle-af~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-ar", rpm:"moodle-ar~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-be", rpm:"moodle-be~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-bg", rpm:"moodle-bg~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-bn", rpm:"moodle-bn~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-bs", rpm:"moodle-bs~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-ca", rpm:"moodle-ca~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-cs", rpm:"moodle-cs~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-cy", rpm:"moodle-cy~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-da", rpm:"moodle-da~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-de", rpm:"moodle-de~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-de_du", rpm:"moodle-de_du~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-el", rpm:"moodle-el~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-es", rpm:"moodle-es~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-et", rpm:"moodle-et~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-eu", rpm:"moodle-eu~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-fa", rpm:"moodle-fa~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-fi", rpm:"moodle-fi~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-fil", rpm:"moodle-fil~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-fr", rpm:"moodle-fr~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-fr_ca", rpm:"moodle-fr_ca~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-ga", rpm:"moodle-ga~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-gl", rpm:"moodle-gl~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-gu", rpm:"moodle-gu~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-he", rpm:"moodle-he~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-hi", rpm:"moodle-hi~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-hr", rpm:"moodle-hr~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-hu", rpm:"moodle-hu~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-hy", rpm:"moodle-hy~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-id", rpm:"moodle-id~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-is", rpm:"moodle-is~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-it", rpm:"moodle-it~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-ja", rpm:"moodle-ja~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-ka", rpm:"moodle-ka~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-kk", rpm:"moodle-kk~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-km", rpm:"moodle-km~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-kn", rpm:"moodle-kn~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-ko", rpm:"moodle-ko~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-lo", rpm:"moodle-lo~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-lt", rpm:"moodle-lt~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-lv", rpm:"moodle-lv~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-mi_tn", rpm:"moodle-mi_tn~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-mi_wwow", rpm:"moodle-mi_wwow~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-mk", rpm:"moodle-mk~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-ml", rpm:"moodle-ml~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-mn", rpm:"moodle-mn~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-ms", rpm:"moodle-ms~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-nl", rpm:"moodle-nl~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-nn", rpm:"moodle-nn~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-no", rpm:"moodle-no~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-no_gr", rpm:"moodle-no_gr~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-pl", rpm:"moodle-pl~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-pt", rpm:"moodle-pt~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-pt_br", rpm:"moodle-pt_br~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-ro", rpm:"moodle-ro~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-ru", rpm:"moodle-ru~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-si", rpm:"moodle-si~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-sk", rpm:"moodle-sk~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-sl", rpm:"moodle-sl~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-sm", rpm:"moodle-sm~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-so", rpm:"moodle-so~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-sq", rpm:"moodle-sq~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-sr_cr", rpm:"moodle-sr_cr~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-sr_cr_bo", rpm:"moodle-sr_cr_bo~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-sr_lt", rpm:"moodle-sr_lt~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-sv", rpm:"moodle-sv~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-ta", rpm:"moodle-ta~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-ta_lk", rpm:"moodle-ta_lk~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-th", rpm:"moodle-th~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-tl", rpm:"moodle-tl~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-to", rpm:"moodle-to~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-tr", rpm:"moodle-tr~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-uk", rpm:"moodle-uk~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-uz", rpm:"moodle-uz~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-vi", rpm:"moodle-vi~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-zh_cn", rpm:"moodle-zh_cn~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"moodle-zh_tw", rpm:"moodle-zh_tw~1.9.4~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
