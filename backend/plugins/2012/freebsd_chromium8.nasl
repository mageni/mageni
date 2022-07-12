###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_chromium8.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 057130e6-7f61-11e1-8a43-00262d5ed8ee
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
  script_oid("1.3.6.1.4.1.25623.1.0.71285");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-3066", "CVE-2011-3067", "CVE-2011-3068", "CVE-2011-3069", "CVE-2011-3070", "CVE-2011-3071", "CVE-2011-3072", "CVE-2011-3073", "CVE-2011-3074", "CVE-2011-3075", "CVE-2011-3076", "CVE-2011-3077");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-04-30 07:59:26 -0400 (Mon, 30 Apr 2012)");
  script_name("FreeBSD Ports: chromium");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: chromium

CVE-2011-3066
Skia, as used in Google Chrome before 18.0.1025.151, does not properly
perform clipping, which allows remote attackers to cause a denial of
service (out-of-bounds read) via unspecified vectors.
CVE-2011-3067
Google Chrome before 18.0.1025.151 allows remote attackers to bypass
the Same Origin Policy via vectors related to replacement of IFRAME
elements.
CVE-2011-3068
Use-after-free vulnerability in the Cascading Style Sheets (CSS)
implementation in Google Chrome before 18.0.1025.151 allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via vectors related to run-in boxes.
CVE-2011-3069
Use-after-free vulnerability in the Cascading Style Sheets (CSS)
implementation in Google Chrome before 18.0.1025.151 allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via vectors related to line boxes.
CVE-2011-3070
Use-after-free vulnerability in Google Chrome before 18.0.1025.151
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to the Google V8
bindings.
CVE-2011-3071
Use-after-free vulnerability in the HTMLMediaElement implementation in
Google Chrome before 18.0.1025.151 allows remote attackers to cause a
denial of service or possibly have unspecified other impact via
unknown vectors.
CVE-2011-3072
Google Chrome before 18.0.1025.151 allows remote attackers to bypass
the Same Origin Policy via vectors related to pop-up windows.
CVE-2011-3073
Use-after-free vulnerability in Google Chrome before 18.0.1025.151
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to the handling of SVG
resources.
CVE-2011-3074
Use-after-free vulnerability in Google Chrome before 18.0.1025.151
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to the handling of media.
CVE-2011-3075
Use-after-free vulnerability in Google Chrome before 18.0.1025.151
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to style-application
commands.
CVE-2011-3076
Use-after-free vulnerability in Google Chrome before 18.0.1025.151
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to focus handling.
CVE-2011-3077
Use-after-free vulnerability in Google Chrome before 18.0.1025.151
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving the script bindings,
related to a 'read-after-free' issue.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/search/label/Stable%20updates");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/057130e6-7f61-11e1-8a43-00262d5ed8ee.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"18.0.1025.151")<0) {
  txt += "Package chromium version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}