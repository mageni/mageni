# OpenVAS Vulnerability Test
# $Id: mdksa_2009_113.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:113 (cyrus-sasl)
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
tag_insight = "Multiple buffer overflows in the CMU Cyrus SASL library before 2.1.23
might allow remote attackers to execute arbitrary code or cause a
denial of service application crash) via strings that are used as
input to the sasl_encode64 function in lib/saslutil.c (CVE-2009-0688).

The updated packages have been patched to prevent this.

Affected: 2008.1, 2009.0, 2009.1, Corporate 3.0, Corporate 4.0,
          Multi Network Firewall 2.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:113";
tag_summary = "The remote host is missing an update to cyrus-sasl
announced via advisory MDVSA-2009:113.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311501");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
 script_cve_id("CVE-2009-0688");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Mandrake Security Advisory MDVSA-2009:113 (cyrus-sasl)");



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
if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2", rpm:"libsasl2~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-devel", rpm:"libsasl2-devel~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-anonymous", rpm:"libsasl2-plug-anonymous~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-crammd5", rpm:"libsasl2-plug-crammd5~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-digestmd5", rpm:"libsasl2-plug-digestmd5~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-gssapi", rpm:"libsasl2-plug-gssapi~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ldapdb", rpm:"libsasl2-plug-ldapdb~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-login", rpm:"libsasl2-plug-login~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ntlm", rpm:"libsasl2-plug-ntlm~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-otp", rpm:"libsasl2-plug-otp~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-plain", rpm:"libsasl2-plug-plain~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sasldb", rpm:"libsasl2-plug-sasldb~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sql", rpm:"libsasl2-plug-sql~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2", rpm:"lib64sasl2~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-devel", rpm:"lib64sasl2-devel~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-anonymous", rpm:"lib64sasl2-plug-anonymous~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-crammd5", rpm:"lib64sasl2-plug-crammd5~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-digestmd5", rpm:"lib64sasl2-plug-digestmd5~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-gssapi", rpm:"lib64sasl2-plug-gssapi~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ldapdb", rpm:"lib64sasl2-plug-ldapdb~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-login", rpm:"lib64sasl2-plug-login~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ntlm", rpm:"lib64sasl2-plug-ntlm~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-otp", rpm:"lib64sasl2-plug-otp~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-plain", rpm:"lib64sasl2-plug-plain~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sasldb", rpm:"lib64sasl2-plug-sasldb~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sql", rpm:"lib64sasl2-plug-sql~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2", rpm:"libsasl2~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-devel", rpm:"libsasl2-devel~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-anonymous", rpm:"libsasl2-plug-anonymous~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-crammd5", rpm:"libsasl2-plug-crammd5~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-digestmd5", rpm:"libsasl2-plug-digestmd5~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-gssapi", rpm:"libsasl2-plug-gssapi~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ldapdb", rpm:"libsasl2-plug-ldapdb~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-login", rpm:"libsasl2-plug-login~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ntlm", rpm:"libsasl2-plug-ntlm~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-otp", rpm:"libsasl2-plug-otp~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-plain", rpm:"libsasl2-plug-plain~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sasldb", rpm:"libsasl2-plug-sasldb~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sql", rpm:"libsasl2-plug-sql~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2", rpm:"lib64sasl2~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-devel", rpm:"lib64sasl2-devel~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-anonymous", rpm:"lib64sasl2-plug-anonymous~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-crammd5", rpm:"lib64sasl2-plug-crammd5~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-digestmd5", rpm:"lib64sasl2-plug-digestmd5~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-gssapi", rpm:"lib64sasl2-plug-gssapi~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ldapdb", rpm:"lib64sasl2-plug-ldapdb~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-login", rpm:"lib64sasl2-plug-login~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ntlm", rpm:"lib64sasl2-plug-ntlm~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-otp", rpm:"lib64sasl2-plug-otp~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-plain", rpm:"lib64sasl2-plug-plain~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sasldb", rpm:"lib64sasl2-plug-sasldb~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sql", rpm:"lib64sasl2-plug-sql~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2", rpm:"libsasl2~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-devel", rpm:"libsasl2-devel~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-anonymous", rpm:"libsasl2-plug-anonymous~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-crammd5", rpm:"libsasl2-plug-crammd5~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-digestmd5", rpm:"libsasl2-plug-digestmd5~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-gssapi", rpm:"libsasl2-plug-gssapi~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ldapdb", rpm:"libsasl2-plug-ldapdb~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-login", rpm:"libsasl2-plug-login~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ntlm", rpm:"libsasl2-plug-ntlm~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-otp", rpm:"libsasl2-plug-otp~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-plain", rpm:"libsasl2-plug-plain~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sasldb", rpm:"libsasl2-plug-sasldb~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sql", rpm:"libsasl2-plug-sql~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2", rpm:"lib64sasl2~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-devel", rpm:"lib64sasl2-devel~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-anonymous", rpm:"lib64sasl2-plug-anonymous~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-crammd5", rpm:"lib64sasl2-plug-crammd5~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-digestmd5", rpm:"lib64sasl2-plug-digestmd5~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-gssapi", rpm:"lib64sasl2-plug-gssapi~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ldapdb", rpm:"lib64sasl2-plug-ldapdb~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-login", rpm:"lib64sasl2-plug-login~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ntlm", rpm:"lib64sasl2-plug-ntlm~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-otp", rpm:"lib64sasl2-plug-otp~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-plain", rpm:"lib64sasl2-plug-plain~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sasldb", rpm:"lib64sasl2-plug-sasldb~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sql", rpm:"lib64sasl2-plug-sql~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2", rpm:"libsasl2~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-devel", rpm:"libsasl2-devel~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-anonymous", rpm:"libsasl2-plug-anonymous~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-crammd5", rpm:"libsasl2-plug-crammd5~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-digestmd5", rpm:"libsasl2-plug-digestmd5~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-gssapi", rpm:"libsasl2-plug-gssapi~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-login", rpm:"libsasl2-plug-login~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ntlm", rpm:"libsasl2-plug-ntlm~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-otp", rpm:"libsasl2-plug-otp~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-plain", rpm:"libsasl2-plug-plain~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sasldb", rpm:"libsasl2-plug-sasldb~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-srp", rpm:"libsasl2-plug-srp~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2", rpm:"lib64sasl2~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-devel", rpm:"lib64sasl2-devel~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-anonymous", rpm:"lib64sasl2-plug-anonymous~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-crammd5", rpm:"lib64sasl2-plug-crammd5~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-digestmd5", rpm:"lib64sasl2-plug-digestmd5~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-gssapi", rpm:"lib64sasl2-plug-gssapi~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-login", rpm:"lib64sasl2-plug-login~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ntlm", rpm:"lib64sasl2-plug-ntlm~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-otp", rpm:"lib64sasl2-plug-otp~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-plain", rpm:"lib64sasl2-plug-plain~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sasldb", rpm:"lib64sasl2-plug-sasldb~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-srp", rpm:"lib64sasl2-plug-srp~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2", rpm:"libsasl2~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-devel", rpm:"libsasl2-devel~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-anonymous", rpm:"libsasl2-plug-anonymous~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-crammd5", rpm:"libsasl2-plug-crammd5~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-digestmd5", rpm:"libsasl2-plug-digestmd5~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-gssapi", rpm:"libsasl2-plug-gssapi~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ldapdb", rpm:"libsasl2-plug-ldapdb~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-login", rpm:"libsasl2-plug-login~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ntlm", rpm:"libsasl2-plug-ntlm~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-otp", rpm:"libsasl2-plug-otp~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-plain", rpm:"libsasl2-plug-plain~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sasldb", rpm:"libsasl2-plug-sasldb~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sql", rpm:"libsasl2-plug-sql~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2", rpm:"lib64sasl2~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-devel", rpm:"lib64sasl2-devel~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-anonymous", rpm:"lib64sasl2-plug-anonymous~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-crammd5", rpm:"lib64sasl2-plug-crammd5~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-digestmd5", rpm:"lib64sasl2-plug-digestmd5~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-gssapi", rpm:"lib64sasl2-plug-gssapi~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ldapdb", rpm:"lib64sasl2-plug-ldapdb~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-login", rpm:"lib64sasl2-plug-login~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ntlm", rpm:"lib64sasl2-plug-ntlm~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-otp", rpm:"lib64sasl2-plug-otp~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-plain", rpm:"lib64sasl2-plug-plain~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sasldb", rpm:"lib64sasl2-plug-sasldb~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sql", rpm:"lib64sasl2-plug-sql~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2", rpm:"libsasl2~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-devel", rpm:"libsasl2-devel~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-anonymous", rpm:"libsasl2-plug-anonymous~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-crammd5", rpm:"libsasl2-plug-crammd5~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-digestmd5", rpm:"libsasl2-plug-digestmd5~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-gssapi", rpm:"libsasl2-plug-gssapi~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-login", rpm:"libsasl2-plug-login~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ntlm", rpm:"libsasl2-plug-ntlm~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-otp", rpm:"libsasl2-plug-otp~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-plain", rpm:"libsasl2-plug-plain~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sasldb", rpm:"libsasl2-plug-sasldb~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-srp", rpm:"libsasl2-plug-srp~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
