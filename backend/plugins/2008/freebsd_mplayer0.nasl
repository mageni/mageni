#
#VID 85d76f02-5380-11d9-a9e7-0001020eed82
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
   mplayer
   mplayer-gtk
   mplayer-gtk2
   mplayer-esound
   mplayer-gtk-esound
   mplayer-gtk2-esound
   libxine

CVE-2004-1187
Heap-based buffer overflow in the pnm_get_chunk function for xine
0.99.2, and other packages such as MPlayer that use the same code,
allows remote attackers to execute arbitrary code via long PNA_TAG
values, a different vulnerability than CVE-2004-1188.

CVE-2004-1188
The pnm_get_chunk function in xine 0.99.2 and earlier, and other
packages such as MPlayer that use the same code, does not properly
verify that the chunk size is less than the PREAMBLE_SIZE, which
causes a read operation with a negative length that leads to a buffer
overflow via (1) RMF_TAG, (2) DATA_TAG, (3) PROP_TAG, (4) MDPR_TAG,
and (5) CONT_TAG values, a different vulnerability than CVE-2004-1187.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://mplayerhq.hu/homepage/design7/news.html#mplayer10pre5try2
http://www.idefense.com/application/poi/display?id=166
http://www.idefense.com/application/poi/display?id=167
http://www.idefense.com/application/poi/display?id=168
http://xinehq.de/index.php/security/XSA-2004-6
http://marc.theaimsgroup.com/?l=bugtraq&m=110322526210300
http://marc.theaimsgroup.com/?l=bugtraq&m=110322829807443
http://marc.theaimsgroup.com/?l=bugtraq&m=110323022605345
http://www.vuxml.org/freebsd/85d76f02-5380-11d9-a9e7-0001020eed82.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301306");
 script_version("$Revision: 4144 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-26 07:28:56 +0200 (Mon, 26 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-1187", "CVE-2004-1188");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("mplayer -- multiple vulnerabilities");



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
bver = portver(pkg:"mplayer");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.5_5")<0) {
    txt += 'Package mplayer version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mplayer-gtk");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.5_5")<0) {
    txt += 'Package mplayer-gtk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mplayer-gtk2");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.5_5")<0) {
    txt += 'Package mplayer-gtk2 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mplayer-esound");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.5_5")<0) {
    txt += 'Package mplayer-esound version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mplayer-gtk-esound");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.5_5")<0) {
    txt += 'Package mplayer-gtk-esound version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mplayer-gtk2-esound");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.5_5")<0) {
    txt += 'Package mplayer-gtk2-esound version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"libxine");
if(!isnull(bver) && revcomp(a:bver, b:"1.0.r5_3")<=0) {
    txt += 'Package libxine version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
