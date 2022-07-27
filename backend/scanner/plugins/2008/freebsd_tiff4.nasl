#
#VID 68222076-010b-11da-bc08-0001020eed82
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
   tiff
   linux-tiff
   pdflib
   pdflib-perl
   fractorama
   gdal
   iv
   ivtools
   ja-iv
   ja-libimg
   paraview

CVE-2005-1544
Stack-based buffer overflow in libTIFF before 1.53 allows remote
attackers to execute arbitrary code via a TIFF file with a malformed
BitsPerSample tag.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://bugzilla.remotesensing.org/show_bug.cgi?id=843
http://www.gentoo.org/security/en/glsa/glsa-200505-07.xml
http://www.remotesensing.org/libtiff/v3.7.3.html
http://www.vuxml.org/freebsd/68222076-010b-11da-bc08-0001020eed82.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300469");
 script_version("$Revision: 4203 $");
 script_tag(name:"last_modification", value:"$Date: 2016-10-04 07:30:30 +0200 (Tue, 04 Oct 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_bugtraq_id(13585);
 script_cve_id("CVE-2005-1544");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: tiff");



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
bver = portver(pkg:"tiff");
if(!isnull(bver) && revcomp(a:bver, b:"3.7.3")<0) {
    txt += 'Package tiff version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-tiff");
if(!isnull(bver) && revcomp(a:bver, b:"3.6.1_3")<0) {
    txt += 'Package linux-tiff version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"pdflib");
if(!isnull(bver) && revcomp(a:bver, b:"6.0.1_2")<0) {
    txt += 'Package pdflib version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"pdflib-perl");
if(!isnull(bver) && revcomp(a:bver, b:"6.0.1_2")<0) {
    txt += 'Package pdflib-perl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"fractorama");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package fractorama version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"gdal");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package gdal version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"iv");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package iv version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ivtools");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package ivtools version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-iv");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package ja-iv version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-libimg");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package ja-libimg version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"paraview");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package paraview version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
