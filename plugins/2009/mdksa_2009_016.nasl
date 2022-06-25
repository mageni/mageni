# OpenVAS Vulnerability Test
# $Id: mdksa_2009_016.nasl 6587 2017-07-07 06:35:35Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:016 (xen)
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
tag_insight = "Ian Jackson found a security issue in the QEMU block device drivers
backend that could allow a guest operating system to issue a block
device request and read or write arbitrary memory locations, which
could then lead to privilege escalation (CVE-2008-0928).

It was found that Xen allowed unprivileged DomU domains to overwrite
xenstore values which should only be changeable by the privileged
Dom0 domain.  An attacker able to control a DomU domain could possibly
use this flaw to kill arbitrary processes in Dom0 or trick a Dom0
user into accessing the text console of a different domain running
on the same host.  This update makes certain parts of xenstore tree
read-only to unprivilged DomU domains (CVE-2008-4405).

A vulnerability in the qemu-dm.debug script was found in how it
created a temporary file in /tmp.  A local attacker in Dom0 could
potentially use this flaw to overwrite arbitrary files via a symlink
attack (CVE-2008-4993).  Since this script is not used in production,
it has been removed from this update package.

The updated packages have been patched to prevent these issues.

Affected: Corporate 4.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:016";
tag_summary = "The remote host is missing an update to xen
announced via advisory MDVSA-2009:016.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310311");
 script_version("$Revision: 6587 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 08:35:35 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-01-20 22:42:09 +0100 (Tue, 20 Jan 2009)");
 script_cve_id("CVE-2008-0928", "CVE-2008-4405", "CVE-2008-4993");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Mandrake Security Advisory MDVSA-2009:016 (xen)");



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
if ((res = isrpmvuln(pkg:"xen", rpm:"xen~3.0.1~3.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
