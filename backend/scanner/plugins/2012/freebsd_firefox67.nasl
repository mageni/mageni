###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_firefox67.nasl 14170 2019-03-14 09:24:12Z cfischer $
#
# Auto generated from VID dbf338d0-dce5-11e1-b655-14dae9ebcf89
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
  script_oid("1.3.6.1.4.1.25623.1.0.71511");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2012-1949", "CVE-2012-1950", "CVE-2012-1951", "CVE-2012-1952", "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1960", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1964", "CVE-2012-1965", "CVE-2012-1966", "CVE-2012-1967");
  script_version("$Revision: 14170 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 10:24:12 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
  script_name("FreeBSD Ports: firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  firefox
   linux-firefox
   linux-seamonkey
   linux-thunderbird
   seamonkey
   thunderbird
   libxul

CVE-2012-1949
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox 4.x through 13.0, Thunderbird 5.0 through 13.0, and SeaMonkey
before 2.11 allow remote attackers to cause a denial of service
(memory corruption and application crash) or possibly execute
arbitrary code via unknown vectors.
CVE-2012-1950
The drag-and-drop implementation in Mozilla Firefox 4.x through 13.0
and Firefox ESR 10.x before 10.0.6 allows remote attackers to spoof
the address bar by canceling a page load.
CVE-2012-1951
Use-after-free vulnerability in the nsSMILTimeValueSpec::IsEventBased
function in Mozilla Firefox 4.x through 13.0, Firefox ESR 10.x before
10.0.6, Thunderbird 5.0 through 13.0, Thunderbird ESR 10.x before
10.0.6, and SeaMonkey before 2.11 allows remote attackers to cause a
denial of service (heap memory corruption) or possibly execute
arbitrary code by interacting with objects used for SMIL Timing.
CVE-2012-1952
The nsTableFrame::InsertFrames function in Mozilla Firefox 4.x through
13.0, Firefox ESR 10.x before 10.0.6, Thunderbird 5.0 through 13.0,
Thunderbird ESR 10.x before 10.0.6, and SeaMonkey before 2.11 does not
properly perform a cast of a frame variable during processing of mixed
row-group and column-group frames, which might allow remote attackers
to execute arbitrary code via a crafted web site.

Text truncated. Please see the references for more information.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/known-vulnerabilities/");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-42.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-43.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-44.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-45.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-46.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-47.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-48.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-49.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-50.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-51.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-52.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-53.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-54.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-55.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-56.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/dbf338d0-dce5-11e1-b655-14dae9ebcf89.html");

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

bver = portver(pkg:"firefox");
if(!isnull(bver) && revcomp(a:bver, b:"11.0,1")>0 && revcomp(a:bver, b:"14.0.1,1")<0) {
  txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"10.0.6,1")<0) {
  txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.6,1")<0) {
  txt += "Package linux-firefox version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"linux-seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.11")<0) {
  txt += "Package linux-seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.6")<0) {
  txt += "Package linux-thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.11")<0) {
  txt += "Package seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"11.0")>0 && revcomp(a:bver, b:"14.0")<0) {
  txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"10.0.6")<0) {
  txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"libxul");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.2")>0 && revcomp(a:bver, b:"10.0.6")<0) {
  txt += "Package libxul version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}