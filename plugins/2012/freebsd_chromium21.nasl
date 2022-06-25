###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_chromium21.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID e6161b65-1187-11e2-afe3-00262d5ed8ee
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
  script_oid("1.3.6.1.4.1.25623.1.0.72479");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2012-2900", "CVE-2012-5108", "CVE-2012-5109", "CVE-2012-5110", "CVE-2012-5111");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-10-13 02:35:34 -0400 (Sat, 13 Oct 2012)");
  script_name("FreeBSD Ports: chromium");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: chromium

CVE-2012-2900
Skia, as used in Google Chrome before 22.0.1229.92, does not properly
render text, which allows remote attackers to cause a denial of
service (application crash) or possibly have unspecified other impact
via unknown vectors.
CVE-2012-5108
Race condition in Google Chrome before 22.0.1229.92 allows remote
attackers to execute arbitrary code via vectors related to audio
devices.
CVE-2012-5109
The International Components for Unicode (ICU) functionality in Google
Chrome before 22.0.1229.92 allows remote attackers to cause a denial
of service (out-of-bounds read) via vectors related to a regular
expression.
CVE-2012-5110
The compositor in Google Chrome before 22.0.1229.92 allows remote
attackers to cause a denial of service (out-of-bounds read) via
unspecified vectors.
CVE-2012-5111
Google Chrome before 22.0.1229.92 does not monitor for crashes of
Pepper plug-ins, which has unspecified impact and remote attack
vectors.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.nl/search/label/Stable%20updates");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/e6161b65-1187-11e2-afe3-00262d5ed8ee.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"22.0.1229.92")<0) {
  txt += "Package chromium version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}