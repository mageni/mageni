# OpenVAS Vulnerability Test
# $Id: fcore_2009_6033.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-6033 (perl)
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
tag_insight = "Update Information:

Off-by-one overflow in Compress::Raw::Zlib (CVE-2009-1391)

ChangeLog:

* Mon Jun  8 2009 Marcela Maláová  - 4:5.10.0-69
- #504386 update of Compress::Raw::Zlib 2.020
- update File::Spec (PathTools) to 3.30
- fix #221113, $! wrongly set when EOF is reached";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update perl' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6033";
tag_summary = "The remote host is missing an update to perl
announced via advisory FEDORA-2009-6033.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308126");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
 script_cve_id("CVE-2009-1391");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Fedora Core 11 FEDORA-2009-6033 (perl)");



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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=504386");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"perl", rpm:"perl~5.10.0~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Archive-Extract", rpm:"perl-Archive-Extract~0.30~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Archive-Tar", rpm:"perl-Archive-Tar~1.46~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-CPAN", rpm:"perl-CPAN~1.9205~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-CPANPLUS", rpm:"perl-CPANPLUS~0.84~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Compress-Raw", rpm:"perl-Compress-Raw~Zlib~2.008", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Compress-Zlib", rpm:"perl-Compress-Zlib~2.008~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Digest-SHA", rpm:"perl-Digest-SHA~5.47~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-ExtUtils-CBuilder", rpm:"perl-ExtUtils-CBuilder~0.24~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-ExtUtils-Embed", rpm:"perl-ExtUtils-Embed~1.28~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-ExtUtils-MakeMaker", rpm:"perl-ExtUtils-MakeMaker~6.36~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-ExtUtils-ParseXS", rpm:"perl-ExtUtils-ParseXS~2.18~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-File-Fetch", rpm:"perl-File-Fetch~0.18~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-IO-Compress", rpm:"perl-IO-Compress~Base~2.008", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-IO-Compress", rpm:"perl-IO-Compress~Zlib~2.008", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-IO-Zlib", rpm:"perl-IO-Zlib~1.07~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-IPC-Cmd", rpm:"perl-IPC-Cmd~0.42~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Locale-Maketext", rpm:"perl-Locale-Maketext~Simple~0.18", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Log-Message", rpm:"perl-Log-Message~0.01~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Log-Message", rpm:"perl-Log-Message~Simple~0.04", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Module-Build", rpm:"perl-Module-Build~0.3200~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Module-CoreList", rpm:"perl-Module-CoreList~2.17~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Module-Load", rpm:"perl-Module-Load~0.12~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Module-Load", rpm:"perl-Module-Load~Conditional~0.30", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Module-Loaded", rpm:"perl-Module-Loaded~0.01~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Module-Pluggable", rpm:"perl-Module-Pluggable~3.60~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Object-Accessor", rpm:"perl-Object-Accessor~0.32~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Package-Constants", rpm:"perl-Package-Constants~0.01~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Params-Check", rpm:"perl-Params-Check~0.26~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Pod-Escapes", rpm:"perl-Pod-Escapes~1.04~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Pod-Simple", rpm:"perl-Pod-Simple~3.07~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Term-UI", rpm:"perl-Term-UI~0.18~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Test-Harness", rpm:"perl-Test-Harness~3.16~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Test-Simple", rpm:"perl-Test-Simple~0.86~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Time-Piece", rpm:"perl-Time-Piece~1.12~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-core", rpm:"perl-core~5.10.0~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-devel", rpm:"perl-devel~5.10.0~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-libs", rpm:"perl-libs~5.10.0~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-suidperl", rpm:"perl-suidperl~5.10.0~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-version", rpm:"perl-version~0.74~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-debuginfo", rpm:"perl-debuginfo~5.10.0~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
