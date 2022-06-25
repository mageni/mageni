###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_ImageMagick8.nasl 11763 2018-10-05 11:31:35Z cfischer $
#
# Auto generated from VID 98690c45-0361-11e2-a391-000c29033c32
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72417");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2012-3438");
  script_bugtraq_id(54716);
  script_version("$Revision: 11763 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 13:31:35 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-09-26 11:20:25 -0400 (Wed, 26 Sep 2012)");
  script_name("FreeBSD Ports: ImageMagick, ImageMagick-nox11");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:
   ImageMagick
   ImageMagick-nox11
   GraphicsMagick
   GraphicsMagick-nox11

CVE-2012-3438
The Magick_png_malloc function in coders/png.c in GraphicsMagick
6.7.8-6 does not use the proper variable type for the allocation size,
which might allow remote attackers to cause a denial of service
(crash) via a crafted PNG file that triggers incorrect memory
allocation.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
software upgrades.");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=844105");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50090");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/77259");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/98690c45-0361-11e2-a391-000c29033c32.html");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"ImageMagick");
if(!isnull(bver) && revcomp(a:bver, b:"6.7.8.6")<=0) {
  txt += "Package ImageMagick version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"ImageMagick-nox11");
if(!isnull(bver) && revcomp(a:bver, b:"6.7.8.6")<=0) {
  txt += "Package ImageMagick-nox11 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"GraphicsMagick");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.0")>=0 && revcomp(a:bver, b:"1.3.16")<=0) {
  txt += "Package GraphicsMagick version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"GraphicsMagick-nox11");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.0")>=0 && revcomp(a:bver, b:"1.3.16")<=0) {
  txt += "Package GraphicsMagick-nox11 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}