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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2009.1751");
  script_cve_id("CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0775", "CVE-2009-0776");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1751)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1751");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1751");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xulrunner' package(s) announced via the DSA-1751 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Xulrunner, a runtime environment for XUL applications, such as the Iceweasel web browser. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0771

Martijn Wargers, Jesse Ruderman and Josh Soref discovered crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2009-0772

Jesse Ruderman discovered crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2009-0773

Gary Kwong, and Timothee Groleau discovered crashes in the Javascript engine, which might allow the execution of arbitrary code.

CVE-2009-0774

Gary Kwong discovered crashes in the Javascript engine, which might allow the execution of arbitrary code.

CVE-2009-0775

It was discovered that incorrect memory management in the DOM element handling may lead to the execution of arbitrary code.

CVE-2009-0776

Georgi Guninski discovered a violation of the same-origin policy through RDFXMLDataSource and cross-domain redirects.

As indicated in the Etch release notes, security support for the Mozilla products in the oldstable distribution needed to be stopped before the end of the regular Etch security maintenance life cycle. You are strongly encouraged to upgrade to stable or switch to a still supported browser.

For the stable distribution (lenny), these problems have been fixed in version 1.9.0.7-0lenny1.

For the unstable distribution (sid), these problems have been fixed in version 1.9.0.7-1.

We recommend that you upgrade your xulrunner packages.");

  script_tag(name:"affected", value:"'xulrunner' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmozillainterfaces-java", ver:"1.9.0.7-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.9.0.7-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs1d-dbg", ver:"1.9.0.7-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs1d", ver:"1.9.0.7-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-xpcom", ver:"1.9.0.7-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.9.0.7-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9-dbg", ver:"1.9.0.7-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.7-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.7-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.0.7-0lenny1", rls:"DEB5"))) {
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
