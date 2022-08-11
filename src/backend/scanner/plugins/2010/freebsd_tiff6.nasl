#
#VID 313da7dc-763b-11df-bcce-0018f3e2eb82
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 313da7dc-763b-11df-bcce-0018f3e2eb82
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
tag_insight = "The following packages are affected:
   tiff
   linux-tiff

CVE-2010-1411
Multiple integer overflows in the Fax3SetupState function in
tif_fax3.c in the FAX3 decoder in LibTIFF before 3.9.3, as used in
ImageIO in Apple Mac OS X 10.5.8 and Mac OS X 10.6 before 10.6.4,
allow remote attackers to execute arbitrary code or cause a denial of
service (application crash) via a crafted TIFF file that triggers a
heap-based buffer overflow.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.remotesensing.org/libtiff/v3.9.3.html
http://support.apple.com/kb/HT4196
http://www.vuxml.org/freebsd/313da7dc-763b-11df-bcce-0018f3e2eb82.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313015");
 script_version("$Revision: 8438 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-07-06 02:35:12 +0200 (Tue, 06 Jul 2010)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-1411");
 script_name("FreeBSD Ports: tiff");



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
bver = portver(pkg:"tiff");
if(!isnull(bver) && revcomp(a:bver, b:"3.9.3")<0) {
    txt += 'Package tiff version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-tiff");
if(!isnull(bver) && revcomp(a:bver, b:"3.9.3")<0) {
    txt += 'Package linux-tiff version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
