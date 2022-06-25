#
#VID 736e55bc-39bb-11de-a493-001b77d09812
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 736e55bc-39bb-11de-a493-001b77d09812
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The following package is affected: cups-base

CVE-2009-0163
Integer overflow in the TIFF image decoding routines in CUPS 1.3.9 and
earlier allows remote attackers to cause a denial of service (daemon
crash) and possibly execute arbitrary code via a crafted TIFF image,
which is not properly handled by the (1) _cupsImageReadTIFF function
in the imagetops filter and (2) imagetoraster filter, leading to a
heap-based buffer overflow.

CVE-2009-0164
The web interface for CUPS before 1.3.10 does not validate the HTTP
Host header in a client request, which makes it easier for remote
attackers to conduct DNS rebinding attacks.

CVE-2009-0146
Multiple buffer overflows in the JBIG2 decoder in Xpdf 3.02pl2 and
earlier, CUPS 1.3.9 and earlier, and other products allow remote
attackers to cause a denial of service (crash) via a crafted PDF file,
related to (1) JBIG2SymbolDict::setBitmap and (2)
JBIG2Stream::readSymbolDictSeg.

CVE-2009-0147
Multiple integer overflows in the JBIG2 decoder in Xpdf 3.02pl2 and
earlier, CUPS 1.3.9 and earlier, and other products allow remote
attackers to cause a denial of service (crash) via a crafted PDF file,
related to (1) JBIG2Stream::readSymbolDictSeg, (2)
JBIG2Stream::readSymbolDictSeg, and (3)
JBIG2Stream::readGenericBitmap.

CVE-2009-0166
The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier,
and other products allows remote attackers to cause a denial of
service (crash) via a crafted PDF file that triggers a free of
uninitialized memory.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.cups.org/articles.php?L582
http://www.vuxml.org/freebsd/736e55bc-39bb-11de-a493-001b77d09812.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305721");
 script_version("$Revision: 4824 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-21 09:49:38 +0100 (Wed, 21 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-05-11 20:24:31 +0200 (Mon, 11 May 2009)");
 script_cve_id("CVE-2009-0163", "CVE-2009-0164", "CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166");
 script_bugtraq_id(34571,34665,34568);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: cups-base");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"cups-base");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.10")<0) {
    txt += 'Package cups-base version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
