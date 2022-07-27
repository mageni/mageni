###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_chromium24.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 4d64fc61-3878-11e2-a4eb-00262d5ed8ee
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
  script_oid("1.3.6.1.4.1.25623.1.0.72632");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2012-5130", "CVE-2012-5132", "CVE-2012-5133", "CVE-2012-5134", "CVE-2012-5135", "CVE-2012-5136");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-12-04 11:43:52 -0500 (Tue, 04 Dec 2012)");
  script_name("FreeBSD Ports: chromium");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: chromium

CVE-2012-5130
Skia, as used in Google Chrome before 23.0.1271.91, allows remote
attackers to cause a denial of service (out-of-bounds read) via
unspecified vectors.
CVE-2012-5132
Google Chrome before 23.0.1271.91 allows remote attackers to cause a
denial of service (application crash) via a response with chunked
transfer coding.
CVE-2012-5133
Use-after-free vulnerability in Google Chrome before 23.0.1271.91
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to SVG filters.
CVE-2012-5134
Heap-based buffer underflow in the xmlParseAttValueComplex function in
parser.c in libxml2 2.9.0 and earlier, as used in Google Chrome before
23.0.1271.91, allows remote attackers to cause a denial of service or
possibly execute arbitrary code via crafted entities in an XML
document.
CVE-2012-5135
Use-after-free vulnerability in Google Chrome before 23.0.1271.91
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to printing.
CVE-2012-5136
Google Chrome before 23.0.1271.91 does not properly perform a cast of
an unspecified variable during handling of the INPUT element, which
allows remote attackers to cause a denial of service or possibly have
unknown other impact via a crafted HTML document.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.nl/search/label/Stable%20updates");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/4d64fc61-3878-11e2-a4eb-00262d5ed8ee.html");

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

bver = portver(pkg:"chromium");
if(!isnull(bver) && revcomp(a:bver, b:"23.0.1271.91")<0) {
  txt += "Package chromium version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}