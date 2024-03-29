#
#VID 30f5ca1d-a90b-11dc-bf13-0211060005df
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
   qemu
   qemu-devel

CVE-2007-6227
QEMU 0.9.0 allows local users of a Windows XP SP2 guest operating
system to overwrite the TranslationBlock (code_gen_buffer) buffer, and
probably have unspecified other impacts related to an 'overflow,' via
certain Windows executable programs, as demonstrated by qemu-dos.com.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.vuxml.org/freebsd/30f5ca1d-a90b-11dc-bf13-0211060005df.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303573");
 script_version("$Revision: 4164 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-28 09:03:16 +0200 (Wed, 28 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2007-6227");
 script_bugtraq_id(26666);
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: qemu, qemu-devel");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"qemu");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.0_4")<0) {
    txt += 'Package qemu version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"0.9.0s.20070101*")>=0 && revcomp(a:bver, b:"0.9.0s.20070802_1")<0) {
    txt += 'Package qemu version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"qemu-devel");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.0_4")<0) {
    txt += 'Package qemu-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"0.9.0s.20070101*")>=0 && revcomp(a:bver, b:"0.9.0s.20070802_1")<0) {
    txt += 'Package qemu-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
