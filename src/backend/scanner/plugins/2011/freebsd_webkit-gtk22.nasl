###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_webkit-gtk22.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 06a12e26-142e-11e0-bea2-0015f2db7bde
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
  script_oid("1.3.6.1.4.1.25623.1.0.68823");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-1791", "CVE-2010-3812", "CVE-2010-3813", "CVE-2010-4197", "CVE-2010-4198", "CVE-2010-4204", "CVE-2010-4206", "CVE-2010-4577");
  script_name("FreeBSD Ports: webkit-gtk2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: webkit-gtk2

CVE-2010-1791
Integer signedness error in WebKit in Apple Safari before 5.0.1 on Mac
OS X 10.5 through 10.6 and Windows, and before 4.1.1 on Mac OS X 10.4,
allows remote attackers to execute arbitrary code or cause a denial of
service via vectors involving a JavaScript array index.

CVE-2010-3812
Integer overflow in the Text::wholeText method in dom/Text.cpp in
WebKit, as used in Apple Safari before 5.0.3 on Mac OS X 10.5 through
10.6 and Windows, and before 4.1.3 on Mac OS X 10.4, webkitgtk before
1.2.6, and possibly other products allows remote attackers to execute
arbitrary code or cause a denial of service via vectors involving Text objects.

CVE-2010-3813
The WebCore::HTMLLinkElement::process function in
WebCore/html/HTMLLinkElement.cpp in WebKit, as used in Apple Safari
before 5.0.3 on Mac OS X 10.5 through 10.6 and Windows, and before
4.1.3 on Mac OS X 10.4, webkitgtk before 1.2.6, and possibly other
products does not verify whether DNS prefetching is enabled when
processing an HTML LINK element, which allows remote attackers to
bypass intended access restrictions, as demonstrated by an HTML e-mail
message that uses a LINK element for X-Confirm-Reading-To
functionality.

CVE-2010-4197
Use-after-free vulnerability in WebKit, as used in Google Chrome
before 7.0.517.44, webkitgtk before 1.2.6, and other products, allows
remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving text editing.

CVE-2010-4198
WebKit, as used in Google Chrome before 7.0.517.44, webkitgtk before
1.2.6, and other products, does not properly handle large text areas,
which allows remote attackers to cause a denial of service or possibly
have unspecified other impact via a crafted HTML document.

CVE-2010-4204
WebKit, as used in Google Chrome before 7.0.517.44, webkitgtk before
1.2.6, and other products, accesses a frame object after this object
has been destroyed, which allows remote attackers to cause a denial of
service or possibly have unspecified other impact via unknown vectors.

CVE-2010-4206
Array index error in the FEBlend::apply function in
WebCore/platform/graphics/filters/FEBlend.cpp in WebKit, as used in
Google Chrome before 7.0.517.44, webkitgtk before 1.2.6, and other
products, allows remote attackers to cause a denial of service and
possibly execute arbitrary code via a crafted SVG document, related to
effects in the application of filters.

CVE-2010-4577
The CSSParser::parseFontFaceSrc function in WebCore/css/CSSParser.cpp
in WebKit, as used in Google Chrome before 8.0.552.224, Chrome OS
before 8.0.552.343, webkitgtk before 1.2.6, and other products does
not properly parse Cascading Style Sheets (CSS) token sequences, which
allows remote attackers to cause a denial of service via a crafted local
font, related to 'Type Confusion.'");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://gitorious.org/webkitgtk/stable/blobs/master/WebKit/gtk/NEWS");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/06a12e26-142e-11e0-bea2-0015f2db7bde.html");

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

bver = portver(pkg:"webkit-gtk2");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.6")<0) {
  txt += 'Package webkit-gtk2 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}