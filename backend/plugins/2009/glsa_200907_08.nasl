#
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from Gentoo's XML based advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
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
tag_insight = "An integer overflow in multiple Ralink wireless drivers might lead to the
execution of arbitrary code with elevated privileges.";
tag_solution = "All external kernel modules have been masked and we recommend that
users unmerge those drivers. The Linux mainline kernel has equivalent
support for these devices and the vulnerability has been resolved in
stable versions of sys-kernel/gentoo-sources.

    # emerge --unmerge 'net-wireless/rt2400'
    # emerge --unmerge 'net-wireless/rt2500'
    # emerge --unmerge 'net-wireless/rt2570'
    # emerge --unmerge 'net-wireless/rt61'
    # emerge --unmerge 'net-wireless/ralink-rt61'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200907-08
http://bugs.gentoo.org/show_bug.cgi?id=257023";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200907-08.";

                                                                                
                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307281");
 script_version("$Revision: 6595 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:19:55 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
 script_cve_id("CVE-2009-0282");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Gentoo Security Advisory GLSA 200907-08 (rt2400 rt2500 rt2570 rt61 ralink-rt61)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Gentoo Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
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

include("pkg-lib-gentoo.inc");

res = "";
report = "";
if ((res = ispkgvuln(pkg:"net-wireless/rt2400", unaffected: make_list(), vulnerable: make_list("le 1.2.2_beta3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-wireless/rt2500", unaffected: make_list(), vulnerable: make_list("le 1.1.0_pre2007071515"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-wireless/rt2570", unaffected: make_list(), vulnerable: make_list("le 20070209"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-wireless/rt61", unaffected: make_list(), vulnerable: make_list("le 1.1.0_beta2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-wireless/ralink-rt61", unaffected: make_list(), vulnerable: make_list("le 1.1.1.0"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
