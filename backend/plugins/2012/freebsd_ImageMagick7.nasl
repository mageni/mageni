###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_ImageMagick7.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 5140dc69-b65e-11e1-9425-001b21614864
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
  script_oid("1.3.6.1.4.1.25623.1.0.71538");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2012-0259", "CVE-2012-0260", "CVE-2012-1798");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
  script_name("FreeBSD Ports: ImageMagick");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: ImageMagick

CVE-2012-0259
The GetEXIFProperty function in magick/property.c in ImageMagick
before 6.7.6-3 allows remote attackers to cause a denial of service
(crash) via a zero value in the component count of an EXIF XResolution
tag in a JPEG file, which triggers an out-of-bounds read.
CVE-2012-0260
The JPEGWarningHandler function in coders/jpeg.c in ImageMagick before
6.7.6-3 allows remote attackers to cause a denial of service (memory
consumption) via a JPEG image with a crafted sequence of restart
markers.
CVE-2012-1798
The TIFFGetEXIFProperties function in coders/tiff.c in ImageMagick
before 6.7.6-3 allows remote attackers to cause a denial of service
(out-of-bounds read and crash) via a crafted EXIF IFD in a TIFF image.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.imagemagick.org/discourse-server/viewtopic.php?f=4&t=20629");
  script_xref(name:"URL", value:"http://www.cert.fi/en/reports/2012/vulnerability635606.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/5140dc69-b65e-11e1-9425-001b21614864.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"ImageMagick");
if(!isnull(bver) && revcomp(a:bver, b:"6.7.6.4")<0) {
  txt += "Package ImageMagick version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}