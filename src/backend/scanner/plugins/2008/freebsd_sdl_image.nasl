#
#VID b1bcab7d-1880-11dd-a914-0016179b2dd5
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
tag_insight = "The following package is affected: sdl_image

CVE-2007-6697
Buffer overflow in the LWZReadByte function in IMG_gif.c in SDL_image
before 1.2.7 allows remote attackers to cause a denial of service
(application crash) or possibly execute arbitrary code via a crafted
GIF file, a similar issue to CVE-2006-4484.  NOTE: some of these
details are obtained from third party information.

CVE-2008-0544
Heap-based buffer overflow in the IMG_LoadLBM_RW function in IMG_lbm.c
in SDL_image before 1.2.7 allows remote attackers to cause a denial of
service (application crash) or possibly execute arbitrary code via a
crafted IFF ILBM file.  NOTE: some of these details are obtained from
third party information.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/28640
http://www.vuxml.org/freebsd/b1bcab7d-1880-11dd-a914-0016179b2dd5.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303724");
 script_version("$Revision: 4188 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-30 07:56:47 +0200 (Fri, 30 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2007-6697", "CVE-2008-0544");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: sdl_image");



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
bver = portver(pkg:"sdl_image");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.6_1")<0) {
    txt += 'Package sdl_image version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
