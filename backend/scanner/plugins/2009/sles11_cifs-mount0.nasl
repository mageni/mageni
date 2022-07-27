#
#VID dbedb3fb1fc74639fa0c893e6c0ad7f6
# OpenVAS Vulnerability Test
# $
# Description: Security update for Samba
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

    cifs-mount
    ldapsmb
    libsmbclient0
    libtalloc1
    libtdb1
    libwbclient0
    samba
    samba-client
    samba-krb-printing
    samba-winbind


More details may also be found by searching for the SuSE
Enterprise Server 11 patch database located at
http://download.novell.com/patch/finder/";

tag_solution = "Please install the updates provided by SuSE.";

if(description)
{
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=539517");
 script_oid("1.3.6.1.4.1.25623.1.0.308839");
 script_version("$Revision: 6666 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-11 15:13:36 +0200 (Tue, 11 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-27 01:37:56 +0100 (Tue, 27 Oct 2009)");
 script_cve_id("CVE-2009-2813", "CVE-2009-2948", "CVE-2009-2906");
 script_tag(name:"cvss_base", value:"6.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
 script_name("SLES11: Security update for Samba");



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
if ((res = isrpmvuln(pkg:"cifs-mount", rpm:"cifs-mount~3.2.7~11.8.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ldapsmb", rpm:"ldapsmb~1.34b~11.8.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~3.2.7~11.8.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtalloc1", rpm:"libtalloc1~3.2.7~11.8.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtdb1", rpm:"libtdb1~3.2.7~11.8.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~3.2.7~11.8.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.2.7~11.8.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.2.7~11.8.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-krb-printing", rpm:"samba-krb-printing~3.2.7~11.8.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.2.7~11.8.2", rls:"SLES11.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
