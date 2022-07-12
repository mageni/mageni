###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_firefox54.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 45f102cd-4456-11e0-9580-4061862b8c22
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.69147");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-1585", "CVE-2011-0051", "CVE-2011-0053", "CVE-2011-0054", "CVE-2011-0055", "CVE-2011-0056", "CVE-2011-0057", "CVE-2011-0058", "CVE-2011-0059", "CVE-2011-0061", "CVE-2011-0062");
  script_name("FreeBSD Ports: firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"CVE-2010-1585
The nsIScriptableUnescapeHTML.parseFragment method in the
ParanoidFragmentSink protection mechanism in Mozilla Firefox before
3.5.17 and 3.6.x before 3.6.14, Thunderbird before 3.1.8, and
SeaMonkey before 2.0.12 does not properly sanitize HTML in a chrome
document.
CVE-2011-0051
Mozilla Firefox before 3.5.17 and 3.6.x before 3.6.14, and SeaMonkey
before 2.0.12, does not properly handle certain recursive eval calls.
CVE-2011-0053
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 3.5.17 and 3.6.x before 3.6.14, Thunderbird before
3.1.8, and SeaMonkey before 2.0.12 allow remote attackers to cause a
denial of service or possibly execute arbitrary code.
CVE-2011-0054
Buffer overflow in the JavaScript engine in Mozilla Firefox before
3.5.17 and 3.6.x before 3.6.14, and SeaMonkey before 2.0.12, might
allow remote attackers to execute arbitrary code.
CVE-2011-0055
Use-after-free vulnerability in the JSON.stringify method in Mozilla
Firefox before 3.5.17 and 3.6.x before 3.6.14, and SeaMonkey before
2.0.12, might allow remote attackers to execute arbitrary code.
CVE-2011-0056
Buffer overflow in the JavaScript engine in Mozilla Firefox before
3.5.17 and 3.6.x before 3.6.14, and SeaMonkey before 2.0.12, might
allow remote attackers to execute arbitrary code.
CVE-2011-0057
Use-after-free vulnerability in the Web Workers implementation in
Mozilla Firefox before 3.5.17 and 3.6.x before 3.6.14, and SeaMonkey
before 2.0.12, allows remote attackers to execute arbitrary code.
CVE-2011-0058
Buffer overflow in Mozilla Firefox before 3.5.17 and 3.6.x before
3.6.14, and SeaMonkey before 2.0.12, on Windows allows remote
attackers to execute arbitrary code or cause a denial of service.
CVE-2011-0059
Cross-site request forgery vulnerability in Mozilla Firefox
before 3.5.17 and 3.6.x before 3.6.14, and SeaMonkey before 2.0.12,
allows remote attackers to hijack the authentication of arbitrary
users.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2011/mfsa2011-01.html");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2011/mfsa2011-02.html");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2011/mfsa2011-03.html");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2011/mfsa2011-04.html");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2011/mfsa2011-05.html");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2011/mfsa2011-06.html");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2011/mfsa2011-07.html");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2011/mfsa2011-08.html");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2011/mfsa2011-09.html");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2011/mfsa2011-10.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/45f102cd-4456-11e0-9580-4061862b8c22.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system as announced in the referenced advisory.
The following packages are affected:

  firefox
   libxul
   linux-firefox
   linux-firefox-devel
   linux-seamonkey
   linux-thunderbird
   seamonkey
   thunderbird");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"firefox");
if(!isnull(bver) && revcomp(a:bver, b:"3.6.*,1")>0 && revcomp(a:bver, b:"3.6.14,1")<0) {
  txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.5.*,1")>0 && revcomp(a:bver, b:"3.5.17,1")<0) {
  txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"libxul");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.2")>0 && revcomp(a:bver, b:"1.9.2.14")<0) {
  txt += 'Package libxul version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"3.6.14,1")<0) {
  txt += 'Package linux-firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-firefox-devel");
if(!isnull(bver) && revcomp(a:bver, b:"3.5.17")<0) {
  txt += 'Package linux-firefox-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>0 && revcomp(a:bver, b:"2.0.12")<0) {
  txt += 'Package linux-seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"3.1")>=0 && revcomp(a:bver, b:"3.1.8")<0) {
  txt += 'Package linux-thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>0 && revcomp(a:bver, b:"2.0.12")<0) {
  txt += 'Package seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"3.1.8")<0) {
  txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}