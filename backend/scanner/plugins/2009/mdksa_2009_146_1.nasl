# OpenVAS Vulnerability Test
# $Id: mdksa_2009_146_1.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:146-1 (imap)
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
tag_insight = "Security vulnerabilities has been identified and fixed in University
of Washington IMAP Toolkit:

Multiple stack-based buffer overflows in (1) University of Washington
IMAP Toolkit 2002 through 2007c, (2) University of Washington Alpine
2.00 and earlier, and (3) Panda IMAP allow (a) local users to gain
privileges by specifying a long folder extension argument on the
command line to the tmail or dmail program; and (b) remote attackers to
execute arbitrary code by sending e-mail to a destination mailbox name
composed of a username and '+' character followed by a long string,
processed by the tmail or possibly dmail program (CVE-2008-5005).

smtp.c in the c-client library in University of Washington IMAP Toolkit
2007b allows remote SMTP servers to cause a denial of service (NULL
pointer dereference and application crash) by responding to the QUIT
command with a close of the TCP connection instead of the expected
221 response code (CVE-2008-5006).

Off-by-one error in the rfc822_output_char function in the RFC822BUFFER
routines in the University of Washington (UW) c-client library, as
used by the UW IMAP toolkit before imap-2007e and other applications,
allows context-dependent attackers to cause a denial of service (crash)
via an e-mail message that triggers a buffer overflow (CVE-2008-5514).

The updated packages have been patched to prevent this. Note that the
software was renamed to c-client starting from Mandriva Linux 2009.0
and only provides the shared c-client library for the imap functions
in PHP.

Update:

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers.

Affected: 2008.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:146-1";
tag_summary = "The remote host is missing an update to imap
announced via advisory MDVSA-2009:146-1.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305593");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
 script_cve_id("CVE-2008-5005", "CVE-2008-5006", "CVE-2008-5514");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Mandriva Security Advisory MDVSA-2009:146-1 (imap)");



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
if ((res = isrpmvuln(pkg:"imap", rpm:"imap~2006j~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imap-devel", rpm:"imap-devel~2006j~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imap-utils", rpm:"imap-utils~2006j~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libc-client-php0", rpm:"libc-client-php0~2006j~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libc-client-php-devel", rpm:"libc-client-php-devel~2006j~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64c-client-php0", rpm:"lib64c-client-php0~2006j~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64c-client-php-devel", rpm:"lib64c-client-php-devel~2006j~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
