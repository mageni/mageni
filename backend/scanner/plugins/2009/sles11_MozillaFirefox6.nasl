#
#VID dbecc804be7d87cf75529f49774665cb
# OpenVAS Vulnerability Test
# $
# Description: Security update for Firefox
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
tag_summary = "The remote host is missing updates to packages that affect
the security of your system.  One or more of the following packages
are affected:

    MozillaFirefox
    MozillaFirefox-branding-SLED
    MozillaFirefox-translations
    libfreebl3
    mozilla-nspr
    mozilla-nss
    mozilla-nss-tools
    mozilla-xulrunner191
    mozilla-xulrunner191-gnomevfs
    mozilla-xulrunner191-translations


More details may also be found by searching for the SuSE
Enterprise Server 11 patch database located at
http://download.novell.com/patch/finder/";

tag_solution = "Please install the updates provided by SuSE.";

if(description)
{
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=534458");
 script_oid("1.3.6.1.4.1.25623.1.0.306700");
 script_version("$Revision: 6666 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-11 15:13:36 +0200 (Tue, 11 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-11 22:58:51 +0200 (Sun, 11 Oct 2009)");
 script_cve_id("CVE-2009-3069", "CVE-2009-3070", "CVE-2009-3071", "CVE-2009-3072", "CVE-2009-3073", "CVE-2009-3075", "CVE-2009-3077", "CVE-2009-3078", "CVE-2009-3079");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("SLES11: Security update for Firefox");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("SuSE Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms");
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
if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.5.3~1.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~3.5~1.1.5", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~3.5.3~1.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.12.3.1~1.2.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.8~1.3.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.12.3.1~1.2.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.12.3.1~1.2.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-xulrunner191", rpm:"mozilla-xulrunner191~1.9.1.3~1.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-xulrunner191-gnomevfs", rpm:"mozilla-xulrunner191-gnomevfs~1.9.1.3~1.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-xulrunner191-translations", rpm:"mozilla-xulrunner191-translations~1.9.1.3~1.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
