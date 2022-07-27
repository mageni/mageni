#
#VID 30866e6c-3c6d-11dd-98c9-00163e000016
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
   vim
   vim-lite
   vim-ruby
   vim6
   vim6-ruby

CVE-2008-2712
Vim 7.1.314, 6.4, and other versions allows user-assisted remote
attackers to execute arbitrary commands via Vim scripts that do not
properly sanitize inputs before invoking the execute or system
functions, as demonstrated using (1) filetype.vim, (2) zipplugin, (3)
xpm.vim, (4) gzip_vim, and (5) netrw.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.rdancer.org/vulnerablevim.html
http://www.vuxml.org/freebsd/30866e6c-3c6d-11dd-98c9-00163e000016.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302458");
 script_version("$Revision: 4203 $");
 script_tag(name:"last_modification", value:"$Date: 2016-10-04 07:30:30 +0200 (Tue, 04 Oct 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2008-2712");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: vim, vim-lite, vim-ruby, vim6, vim6-ruby");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"vim");
if(!isnull(bver) && revcomp(a:bver, b:"6")>0 && revcomp(a:bver, b:"6.4.10")<=0) {
    txt += 'Package vim version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"7")>0 && revcomp(a:bver, b:"7.1.315")<0) {
    txt += 'Package vim version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"vim-lite");
if(!isnull(bver) && revcomp(a:bver, b:"6")>0 && revcomp(a:bver, b:"6.4.10")<=0) {
    txt += 'Package vim-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"7")>0 && revcomp(a:bver, b:"7.1.315")<0) {
    txt += 'Package vim-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"vim-ruby");
if(!isnull(bver) && revcomp(a:bver, b:"6")>0 && revcomp(a:bver, b:"6.4.10")<=0) {
    txt += 'Package vim-ruby version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"7")>0 && revcomp(a:bver, b:"7.1.315")<0) {
    txt += 'Package vim-ruby version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"vim6");
if(!isnull(bver) && revcomp(a:bver, b:"6")>0 && revcomp(a:bver, b:"6.4.10")<=0) {
    txt += 'Package vim6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"7")>0 && revcomp(a:bver, b:"7.1.315")<0) {
    txt += 'Package vim6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"vim6-ruby");
if(!isnull(bver) && revcomp(a:bver, b:"6")>0 && revcomp(a:bver, b:"6.4.10")<=0) {
    txt += 'Package vim6-ruby version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"7")>0 && revcomp(a:bver, b:"7.1.315")<0) {
    txt += 'Package vim6-ruby version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
