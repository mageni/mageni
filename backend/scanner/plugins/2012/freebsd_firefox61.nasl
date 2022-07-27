###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_firefox61.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 6c8ad3e8-0a30-11e1-9580-4061862b8c22
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
  script_oid("1.3.6.1.4.1.25623.1.0.70609");
  script_tag(name:"creation_date", value:"2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3649", "CVE-2011-3650", "CVE-2011-3651", "CVE-2011-3652", "CVE-2011-3653", "CVE-2011-3654", "CVE-2011-3655");
  script_version("$Revision: 11762 $");
  script_name("FreeBSD Ports: firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  firefox
   libxul
   linux-firefox
   linux-thunderbird
   thunderbird

CVE-2011-3647
The JSSubScriptLoader in Mozilla Firefox before 3.6.24 and Thunderbird
before 3.1.6 does not properly handle XPCNativeWrappers during calls
to the loadSubScript method in an add-on, which makes it easier for
remote attackers to gain privileges via a crafted web site that
leverages certain unwrapping behavior, a related issue to
CVE-2011-3004.

CVE-2011-3648
Cross-site scripting (XSS) vulnerability in Mozilla Firefox before
3.6.24 and 4.x through 7.0 and Thunderbird before 3.1.6 and 5.0
through 7.0 allows remote attackers to inject arbitrary web script or
HTML via crafted text with Shift JIS encoding.

CVE-2011-3649
Mozilla Firefox 7.0 and Thunderbird 7.0, when the Direct2D (aka D2D)
API is used on Windows in conjunction with the Azure graphics
back-end, allow remote attackers to bypass the Same Origin Policy, and
obtain sensitive image data from a different domain, by inserting this
data into a canvas.  NOTE: this issue exists because of a CVE-2011-2986
regression.

CVE-2011-3650
Mozilla Firefox before 3.6.24 and 4.x through 7.0 and Thunderbird
before 3.1.6 and 5.0 through 7.0 do not properly handle JavaScript
files that contain many functions, which allows user-assisted remote
attackers to cause a denial of service (memory corruption and
application crash) or possibly have unspecified other impact via a
crafted file that is accessed by debugging APIs, as demonstrated by
Firebug.

CVE-2011-3651
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox 7.0 and Thunderbird 7.0 allow remote attackers to cause a
denial of service (memory corruption and application crash) or
possibly execute arbitrary code via unknown vectors.

CVE-2011-3652
The browser engine in Mozilla Firefox before 8.0 and Thunderbird
before 8.0 does not properly allocate memory, which allows remote
attackers to cause a denial of service (memory corruption and
application crash) or possibly execute arbitrary code via unspecified
vectors.

CVE-2011-3653
Mozilla Firefox before 8.0 and Thunderbird before 8.0 on Mac OS X do
not properly interact with the GPU memory behavior of a certain driver
for Intel integrated GPUs, which allows remote attackers to bypass the
Same Origin Policy and read image data via vectors related to WebGL
textures.

CVE-2011-3654
The browser engine in Mozilla Firefox before 8.0 and Thunderbird
before 8.0 does not properly handle links from SVG mpath elements to
non-SVG elements, which allows remote attackers to cause a denial of
service (memory corruption and application crash) or possibly execute
arbitrary code via unspecified vectors.

CVE-2011-3655
Mozilla Firefox 4.x through 7.0 and Thunderbird 5.0 through 7.0
perform access control without checking for use of the NoWaiverWrapper
wrapper, which allows remote attackers to gain privileges via a
crafted web site.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-46.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-47.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-48.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-49.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-50.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-51.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-52.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/6c8ad3e8-0a30-11e1-9580-4061862b8c22.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"4.0,1")>0 && revcomp(a:bver, b:"8.0,1")<0) {
  txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.6.*,1")>0 && revcomp(a:bver, b:"3.6.24,1")<0) {
  txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"libxul");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.2")>0 && revcomp(a:bver, b:"1.9.2.24")<0) {
  txt += 'Package libxul version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"8.0,1")<0) {
  txt += 'Package linux-firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"8.0")<0) {
  txt += 'Package linux-thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"4.0")>0 && revcomp(a:bver, b:"8.0")<0) {
  txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.1.16")<0) {
  txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}