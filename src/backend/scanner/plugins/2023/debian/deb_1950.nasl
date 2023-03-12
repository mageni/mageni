# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2009.1950");
  script_cve_id("CVE-2009-0945", "CVE-2009-1681", "CVE-2009-1684", "CVE-2009-1687", "CVE-2009-1690", "CVE-2009-1692", "CVE-2009-1693", "CVE-2009-1694", "CVE-2009-1695", "CVE-2009-1697", "CVE-2009-1698", "CVE-2009-1710", "CVE-2009-1711", "CVE-2009-1712", "CVE-2009-1714", "CVE-2009-1725");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1950)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1950");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1950");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'webkit' package(s) announced via the DSA-1950 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in WebKit, a Web content engine library for Gtk+. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0945

Array index error in the insertItemBefore method in WebKit, allows remote attackers to execute arbitrary code via a document with a SVGPathList data structure containing a negative index in the SVGTransformList, SVGStringList, SVGNumberList, SVGPathSegList, SVGPointList, or SVGLengthList SVGList object, which triggers memory corruption.

CVE-2009-1687

The JavaScript garbage collector in WebKit does not properly handle allocation failures, which allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted HTML document that triggers write access to an 'offset of a NULL pointer.'

CVE-2009-1690

Use-after-free vulnerability in WebKit, allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) by setting an unspecified property of an HTML tag that causes child elements to be freed and later accessed when an HTML error occurs, related to 'recursion in certain DOM event handlers.'

CVE-2009-1698

WebKit does not initialize a pointer during handling of a Cascading Style Sheets (CSS) attr function call with a large numerical argument, which allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted HTML document.

CVE-2009-1711

WebKit does not properly initialize memory for Attr DOM objects, which allows remote attackers to execute arbitrary code or cause a denial of service (application crash) via a crafted HTML document.

CVE-2009-1712

WebKit does not prevent remote loading of local Java applets, which allows remote attackers to execute arbitrary code, gain privileges, or obtain sensitive information via an APPLET or OBJECT element.

CVE-2009-1725

WebKit do not properly handle numeric character references, which allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted HTML document.

CVE-2009-1714

Cross-site scripting (XSS) vulnerability in Web Inspector in WebKit allows user-assisted remote attackers to inject arbitrary web script or HTML, and read local files, via vectors related to the improper escaping of HTML attributes.

CVE-2009-1710

WebKit allows remote attackers to spoof the browser's display of the host name, security indicators, and unspecified other UI elements via a custom cursor in conjunction with a modified CSS3 hotspot property.

CVE-2009-1697

CRLF injection vulnerability in WebKit allows remote attackers to inject HTTP headers and bypass the Same Origin Policy via a crafted HTML document, related to cross-site scripting (XSS) attacks that depend on communication with ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'webkit' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit-1.0-1-dbg", ver:"1.0.1-4+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit-1.0-1", ver:"1.0.1-4+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit-dev", ver:"1.0.1-4+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
