# OpenVAS Vulnerability Test
# $Id: mdksa_2009_342.nasl 6587 2017-07-07 06:35:35Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:342 (acpid)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in acpid:

A certain Red Hat patch for acpid 1.0.4 effectively triggers a call
to the open function with insufficient arguments, which might allow
local users to leverage weak permissions on /var/log/acpid, and obtain
sensitive information by reading this file, cause a denial of service
by overwriting this file, or gain privileges by executing this file
(CVE-2009-4033).

acpid 1.0.4 sets an unrestrictive umask, which might allow local users
to leverage weak permissions on /var/log/acpid, and obtain sensitive
information by reading this file or cause a denial of service by
overwriting this file, a different vulnerability than CVE-2009-4033
(CVE-2009-4235).

This update provides a solution to these vulnerabilities.

Affected: Corporate 4.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:342";
tag_summary = "The remote host is missing an update to acpid
announced via advisory MDVSA-2009:342.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306626");
 script_version("$Revision: 6587 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 08:35:35 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
 script_cve_id("CVE-2009-4033", "CVE-2009-4235");
 script_tag(name:"cvss_base", value:"6.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Mandriva Security Advisory MDVSA-2009:342 (acpid)");



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
if ((res = isrpmvuln(pkg:"acpid", rpm:"acpid~1.0.4~6.4.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
