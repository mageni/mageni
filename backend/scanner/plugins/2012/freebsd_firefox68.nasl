###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_firefox68.nasl 14170 2019-03-14 09:24:12Z cfischer $
#
# Auto generated from VID bfecf7c1-af47-11e1-9580-4061862b8c22
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
  script_oid("1.3.6.1.4.1.25623.1.0.71541");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-3101", "CVE-2012-0441", "CVE-2012-1938", "CVE-2012-1939", "CVE-2012-1937", "CVE-2012-1940", "CVE-2012-1941", "CVE-2012-1944", "CVE-2012-1945", "CVE-2012-1946", "CVE-2012-1947");
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

CVE-2011-3101
Google Chrome before 19.0.1084.46 on Linux does not properly mitigate
an unspecified flaw in an NVIDIA driver, which has unknown impact and
attack vectors.  NOTE: see CVE-2012-3105 for the related MFSA 2012-34
issue in Mozilla products.
CVE-2012-0441
The ASN.1 decoder in the QuickDER decoder in Mozilla Network Security
Services (NSS) before 3.13.4, as used in Firefox 4.x through 12.0,
Firefox ESR 10.x before 10.0.5, Thunderbird 5.0 through 12.0,
Thunderbird ESR 10.x before 10.0.5, and SeaMonkey before 2.10, allows
remote attackers to cause a denial of service (application crash) via
a zero-length item, as demonstrated by (1) a zero-length basic
constraint or (2) a zero-length field in an OCSP response.
CVE-2012-1938
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 13.0, Thunderbird before 13.0, and SeaMonkey before
2.10 allow remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute arbitrary code
via vectors related to (1) methodjit/ImmutableSync.cpp, (2) the
JSObject::makeDenseArraySlow function in js/src/jsarray.cpp, and
unknown other components.

Text truncated. Please see the references for more information.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/known-vulnerabilities/");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-34.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-36.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-37.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-38.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-39.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-40.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/bfecf7c1-af47-11e1-9580-4061862b8c22.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"11.0,1")>0 && revcomp(a:bver, b:"13.0,1")<0) {
  txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"10.0.5,1")<0) {
  txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.5,1")<0) {
  txt += "Package linux-firefox version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"linux-seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.10")<0) {
  txt += "Package linux-seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.5")<0) {
  txt += "Package linux-thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.10")<0) {
  txt += "Package seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"11.0")>0 && revcomp(a:bver, b:"13.0")<0) {
  txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"10.0.5")<0) {
  txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"libxul");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.2")>0 && revcomp(a:bver, b:"10.0.5")<0) {
  txt += "Package libxul version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}