#
#VID 800e8bd5-3acb-11dd-8842-001302a18722
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
tag_insight = "The following package is affected: xorg-server

CVE-2008-1377
The (1) SProcRecordCreateContext and (2) SProcRecordRegisterClients
functions in the Record extension and the (3)
SProcSecurityGenerateAuthorization function in the Security extension
in the X server 1.4 in X.Org X11R7.3 allow context-dependent attackers
to execute arbitrary code via requests with crafted length values that
specify an arbitrary number of bytes to be swapped on the heap, which
triggers heap corruption.

CVE-2008-1379
Integer overflow in the fbShmPutImage function in the MIT-SHM
extension in the X server 1.4 in X.Org X11R7.3 allows
context-dependent attackers to read arbitrary process memory via
crafted values for a Pixmap width and height.

CVE-2008-2360
Integer overflow in the AllocateGlyph function in the Render extension
in the X server 1.4 in X.Org X11R7.3 allows context-dependent
attackers to execute arbitrary code via unspecified request fields
that are used to calculate a heap buffer size, which triggers a
heap-based buffer overflow.

CVE-2008-2361
Integer overflow in the ProcRenderCreateCursor function in the Render
extension in the X server 1.4 in X.Org X11R7.3 allows
context-dependent attackers to cause a denial of service (daemon
crash) via unspecified request fields that are used to calculate a
glyph buffer size, which triggers a dereference of unmapped memory.

CVE-2008-2362
Multiple integer overflows in the Render extension in the X server 1.4
in X.Org X11R7.3 allow context-dependent attackers to execute
arbitrary code via a (1) SProcRenderCreateLinearGradient, (2)
SProcRenderCreateRadialGradient, or (3)
SProcRenderCreateConicalGradient request with an invalid field
specifying the number of bytes to swap in the request data, which
triggers heap memory corruption.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://lists.freedesktop.org/archives/xorg/2008-June/036026.html
http://secunia.com/advisories/30627/
http://www.vuxml.org/freebsd/800e8bd5-3acb-11dd-8842-001302a18722.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300073");
 script_version("$Revision: 4218 $");
 script_tag(name:"last_modification", value:"$Date: 2016-10-05 16:20:48 +0200 (Wed, 05 Oct 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2008-1377", "CVE-2008-1379", "CVE-2008-2360", "CVE-2008-2361", "CVE-2008-2362");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: xorg-server");



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
bver = portver(pkg:"xorg-server");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.2,1")<0) {
    txt += 'Package xorg-server version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
