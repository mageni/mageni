#
#VID 827bc2b7-95ed-11df-9160-00e0815b8da8
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 827bc2b7-95ed-11df-9160-00e0815b8da8
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The following package is affected: git

CVE-2010-2542
Stack-based buffer overflow in the is_git_directory function in
setup.c in Git before 1.7.2.1 allows local users to gain privileges
via a long gitdir: field in a .git file in a working copy.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://git.kernel.org/?p=git/git.git;a=commit;h=3c9d0414ed2db0167e6c828b547be8fc9f88fccc
http://www.openwall.com/lists/oss-security/2010/07/22/1
http://www.vuxml.org/freebsd/827bc2b7-95ed-11df-9160-00e0815b8da8.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314263");
 script_version("$Revision: 8274 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-03 08:28:17 +0100 (Wed, 03 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-08-21 08:54:16 +0200 (Sat, 21 Aug 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-2542");
 script_name("FreeBSD Ports: git");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
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

include("pkg-lib-bsd.inc");

txt = "";
vuln = 0;
bver = portver(pkg:"git");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.6")>=0 && revcomp(a:bver, b:"1.7.1.1_1")<0) {
    txt += 'Package git version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
