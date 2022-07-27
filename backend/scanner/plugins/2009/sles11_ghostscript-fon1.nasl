#
#VID ab7a3ecdd7f2b22db74d66fd6e23832b
# OpenVAS Vulnerability Test
# $
# Description: Security update for GhostScript
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

    ghostscript-fonts-other
    ghostscript-fonts-rus
    ghostscript-fonts-std
    ghostscript-library
    ghostscript-omni
    ghostscript-x11
    libgimpprint


More details may also be found by searching for the SuSE
Enterprise Server 11 patch database located at
http://download.novell.com/patch/finder/";

tag_solution = "Please install the updates provided by SuSE.";

if(description)
{
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=489622");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=491897");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=492765");
 script_oid("1.3.6.1.4.1.25623.1.0.307768");
 script_version("$Revision: 6666 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-11 15:13:36 +0200 (Tue, 11 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-11 22:58:51 +0200 (Sun, 11 Oct 2009)");
 script_cve_id("CVE-2009-0196", "CVE-2009-0792", "CVE-2008-6679", "CVE-2007-6725");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("SLES11: Security update for GhostScript");



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
if ((res = isrpmvuln(pkg:"ghostscript-fonts-other", rpm:"ghostscript-fonts-other~8.62~32.25.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-fonts-rus", rpm:"ghostscript-fonts-rus~8.62~32.25.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-fonts-std", rpm:"ghostscript-fonts-std~8.62~32.25.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-library", rpm:"ghostscript-library~8.62~32.25.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-omni", rpm:"ghostscript-omni~8.62~32.25.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-x11", rpm:"ghostscript-x11~8.62~32.25.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgimpprint", rpm:"libgimpprint~4.2.7~32.25.1", rls:"SLES11.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
