#
#VID f83530b04e1e6fec95e4bd724fa49d7f
# OpenVAS Vulnerability Test
# $
# Description: Security update for KDE4 PIM packages
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

    kde4-akonadi
    kde4-akregator
    kde4-kaddressbook
    kde4-kalarm
    kde4-kjots
    kde4-kmail
    kde4-knode
    kde4-knotes
    kde4-kontact
    kde4-korganizer
    kde4-ktimetracker
    kde4-ktnef
    kdepim4
    kdepim4-wizards
    kdepimlibs4
    libakonadi4
    libkdepim4
    libkdepimlibs4

More details may also be found by searching for the SuSE
Enterprise Server 11 patch database located at
http://download.novell.com/patch/finder/";

tag_solution = "Please install the updates provided by SuSE.";

if(description)
{
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=490696");
 script_oid("1.3.6.1.4.1.25623.1.0.306050");
 script_version("$Revision: 6666 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-11 15:13:36 +0200 (Tue, 11 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-11 22:58:51 +0200 (Sun, 11 Oct 2009)");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
 script_name("SLES11: Security update for KDE4 PIM packages");



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
if ((res = isrpmvuln(pkg:"kde4-akonadi", rpm:"kde4-akonadi~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-akregator", rpm:"kde4-akregator~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-kaddressbook", rpm:"kde4-kaddressbook~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-kalarm", rpm:"kde4-kalarm~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-kjots", rpm:"kde4-kjots~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-kmail", rpm:"kde4-kmail~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-knode", rpm:"kde4-knode~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-knotes", rpm:"kde4-knotes~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-kontact", rpm:"kde4-kontact~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-korganizer", rpm:"kde4-korganizer~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-ktimetracker", rpm:"kde4-ktimetracker~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-ktnef", rpm:"kde4-ktnef~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdepim4", rpm:"kdepim4~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdepim4-wizards", rpm:"kdepim4-wizards~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdepimlibs4", rpm:"kdepimlibs4~4.1.3~9.28.3", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libakonadi4", rpm:"libakonadi4~4.1.3~9.28.3", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdepim4", rpm:"libkdepim4~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdepimlibs4", rpm:"libkdepimlibs4~4.1.3~9.28.3", rls:"SLES11.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
