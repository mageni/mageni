#
#VID c62dc69f-05c8-11d9-b45d-000c41e2cdad
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
   openoffice
   ar-openoffice
   ca-openoffice
   cs-openoffice
   de-openoffice
   dk-openoffice
   el-openoffice
   es-openoffice
   et-openoffice
   fi-openoffice
   fr-openoffice
   gr-openoffice
   hu-openoffice
   it-openoffice
   ja-openoffice
   ko-openoffice
   nl-openoffice
   pl-openoffice
   pt-openoffice
   pt_BR-openoffice
   ru-openoffice
   se-openoffice
   sk-openoffice
   sl-openoffice-SI
   tr-openoffice
   zh-openoffice-CN
   zh-openoffice-TW

CVE-2004-0752
OpenOffice (OOo) 1.1.2 creates predictable directory names with
insecure permissions during startup, which may allow local users to
read or list files of other users.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.openoffice.org/issues/show_bug.cgi?id=33357
http://securitytracker.com/alerts/2004/Sep/1011205.html
http://marc.theaimsgroup.com/?l=bugtraq&m=109483308421566
http://www.vuxml.org/freebsd/c62dc69f-05c8-11d9-b45d-000c41e2cdad.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303085");
 script_version("$Revision: 4144 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-26 07:28:56 +0200 (Mon, 26 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_bugtraq_id(11151);
 script_cve_id("CVE-2004-0752");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_name("openoffice -- document disclosure");



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
bver = portver(pkg:"openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ar-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package ar-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package ar-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ca-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package ca-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package ca-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"cs-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package cs-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package cs-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"de-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package de-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package de-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"dk-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package dk-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package dk-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"el-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package el-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package el-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"es-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package es-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package es-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"et-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package et-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package et-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"fi-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package fi-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package fi-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"fr-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package fr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package fr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"gr-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package gr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package gr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"hu-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package hu-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package hu-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"it-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package it-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package it-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package ja-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package ja-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ko-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package ko-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package ko-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"nl-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package nl-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package nl-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"pl-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package pl-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package pl-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"pt-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package pt-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package pt-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"pt_BR-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package pt_BR-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package pt_BR-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ru-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package ru-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package ru-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"se-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package se-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package se-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"sk-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package sk-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package sk-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"sl-openoffice-SI");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package sl-openoffice-SI version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package sl-openoffice-SI version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"tr-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package tr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package tr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"zh-openoffice-CN");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package zh-openoffice-CN version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package zh-openoffice-CN version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"zh-openoffice-TW");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
    txt += 'Package zh-openoffice-TW version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
    txt += 'Package zh-openoffice-TW version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
