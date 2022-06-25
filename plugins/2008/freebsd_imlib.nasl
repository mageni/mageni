#
#VID 2001103a-6bbd-11d9-851d-000a95bc6fae
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from vuxml or freebsd advisories
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The following packages are affected:
   imlib
   imlib2

CVE-2004-1025
Multiple heap-based buffer overflows in imlib 1.9.14 and earlier,
which is used by gkrellm and several window managers, allow remote
attackers to cause a denial of service (application crash) and execute
arbitrary code via certain image files.

CVE-2004-1026
Multiple integer overflows in the image handler for imlib 1.9.14 and
earlier, which is used by gkrellm and several window managers, allow
remote attackers to cause a denial of service (application crash) and
execute arbitrary code via certain image files.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://bugzilla.fedora.us/show_bug.cgi?id=2051#c11
https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=138516
http://cvs.sourceforge.net/viewcvs.py/enlightenment/e17/libs/imlib2/src/modules/loaders/loader_xpm.c#rev1.3
http://www.vuxml.org/freebsd/2001103a-6bbd-11d9-851d-000a95bc6fae.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301473");
 script_version("$Revision: 4125 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-21 07:39:51 +0200 (Wed, 21 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-1025", "CVE-2004-1026");
 script_bugtraq_id(11830);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: imlib");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"imlib");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.15_2")<0) {
    txt += 'Package imlib version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"imlib2");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package imlib2 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
