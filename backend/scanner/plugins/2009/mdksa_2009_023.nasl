# OpenVAS Vulnerability Test
# $Id: mdksa_2009_023.nasl 6587 2017-07-07 06:35:35Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:023 (php)
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
tag_insight = "A vulnerability in PHP allowed context-dependent attackers to cause
a denial of service (crash) via a certain long string in the glob()
or fnmatch() functions (CVE-2007-4782).

A vulnerability in the cURL library in PHP allowed context-dependent
attackers to bypass safe_mode and open_basedir restrictions and read
arbitrary files using a special URL request (CVE-2007-4850).

An integer overflow in PHP allowed context-dependent attackers to
cause a denial of serivce via a special printf() format parameter
(CVE-2008-1384).

A stack-based buffer overflow in the FastCGI SAPI in PHP has unknown
impact and attack vectors (CVE-2008-2050).

Tavis Ormandy of the Google Security Team discovered a heap-based
buffer overflow when compiling certain regular expression patterns.
This could be used by a malicious attacker by sending a specially
crafted regular expression to an application using the PCRE library,
resulting in the possible execution of arbitrary code or a denial of
service (CVE-2008-2371).  PHP in Corporate Server 4.0 is affected by
this issue.

A buffer overflow in the imageloadfont() function in PHP allowed
context-dependent attackers to cause a denial of service (crash)
and potentially execute arbitrary code via a crafted font file
(CVE-2008-3658).

A buffer overflow in the memnstr() function allowed context-dependent
attackers to cause a denial of service (crash) and potentially execute
arbitrary code via the delimiter argument to the explode() function
(CVE-2008-3659).

PHP, when used as a FastCGI module, allowed remote attackers to cause
a denial of service (crash) via a request with multiple dots preceding
the extension (CVE-2008-3660).

An array index error in the imageRotate() function in PHP allowed
context-dependent attackers to read the contents of arbitrary memory
locations via a crafted value of the third argument to the function
for an indexed image (CVE-2008-5498).

The updated packages have been patched to correct these issues.

Affected: Corporate 4.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:023";
tag_summary = "The remote host is missing an update to php
announced via advisory MDVSA-2009:023.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305951");
 script_version("$Revision: 6587 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 08:35:35 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-01-26 18:18:20 +0100 (Mon, 26 Jan 2009)");
 script_cve_id("CVE-2007-4782", "CVE-2007-4850", "CVE-2008-1384", "CVE-2008-2050", "CVE-2008-2371", "CVE-2008-3658", "CVE-2008-3659", "CVE-2008-3660", "CVE-2008-5498");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Mandrake Security Advisory MDVSA-2009:023 (php)");



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
if ((res = isrpmvuln(pkg:"libphp5_common5", rpm:"libphp5_common5~5.1.6~1.10.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-cgi", rpm:"php-cgi~5.1.6~1.10.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~5.1.6~1.10.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-curl", rpm:"php-curl~5.1.6~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~5.1.6~1.10.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-fcgi", rpm:"php-fcgi~5.1.6~1.10.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-pcre", rpm:"php-pcre~5.1.6~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64php5_common5", rpm:"lib64php5_common5~5.1.6~1.10.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
