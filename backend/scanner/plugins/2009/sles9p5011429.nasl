# OpenVAS Vulnerability Test
# $Id: sles9p5011429.nasl 6666 2017-07-11 13:13:36Z cfischer $
# Description: Security update for Linux kernel
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
tag_summary = "The remote host is missing updates to packages that affect
the security of your system.  One or more of the following packages
are affected:

    um-host-install-initrd
    kernel-smp
    kernel-source
    kernel-debug
    um-host-kernel
    kernel-bigsmp
    kernel-um
    kernel-syms
    kernel-default

For more information, please visit the referenced security
advisories.

More details may also be found by searching for keyword
5011429 within the SuSE Enterprise Server 9 patch
database at http://download.novell.com/patch/finder/";

tag_solution = "Please install the updates provided by SuSE.";
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309647");
 script_version("$Revision: 6666 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-11 15:13:36 +0200 (Tue, 11 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-10 16:11:46 +0200 (Sat, 10 Oct 2009)");
 script_cve_id("CVE-2006-2936", "CVE-2006-5871", "CVE-2006-6106", "CVE-2006-6535", "CVE-2006-5749", "CVE-2006-5753", "CVE-2006-5754", "CVE-2007-1357", "CVE-2007-1592", "CVE-2007-1353", "CVE-2006-7203");
 script_tag(name:"cvss_base", value:"9.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");
 script_name("SLES9: Security update for Linux kernel");



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
if ((res = isrpmvuln(pkg:"um-host-install-initrd", rpm:"um-host-install-initrd~1.0~48.22", rls:"SLES9.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
