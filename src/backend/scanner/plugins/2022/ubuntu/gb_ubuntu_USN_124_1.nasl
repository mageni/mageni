# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.124.1");
  script_cve_id("CVE-2005-1153", "CVE-2005-1154", "CVE-2005-1155", "CVE-2005-1156", "CVE-2005-1157", "CVE-2005-1158", "CVE-2005-1159", "CVE-2005-1160");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-124-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU5\.04");

  script_xref(name:"Advisory-ID", value:"USN-124-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-124-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla, mozilla-firefox' package(s) announced via the USN-124-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"When a popup is blocked the user is given the ability to open that
popup through the popup-blocking status bar icon and, in Firefox,
through the information bar. Doron Rosenberg noticed that popups
which are permitted by the user were executed with elevated
privileges, which could be abused to automatically install and execute
arbitrary code with the privileges of the user. (CAN-2005-1153)

It was discovered that the browser did not start with a clean global
JavaScript state for each new website. This allowed a malicious web
page to define a global variable known to be used by a different site,
allowing malicious code to be executed in the context of that site
(for example, sending web mail or automatic purchasing).
(CAN-2005-1154)

Michael Krax discovered a flaw in the 'favicon' links handler. A
malicious web page could define a favicon link tag as JavaScript,
which could be exploited to execute arbitrary code with the privileges
of the user. (CAN-2005-1155)

Michael Krax found two flaws in the Search Plugin installation. This
allowed malicious plugins to execute arbitrary code in the context of
the current site. If the current page had elevated privileges (like
'about:plugins' or 'about:config'), the malicious plugin could even
install malicious software when a search was performed.
(CAN-2005-1156, CAN-2005-1157)

Kohei Yoshino discovered two missing security checks when Firefox
opens links in its sidebar. This allowed a malicious web page to
construct a link that, when clicked on, could execute arbitrary
JavaScript code with the privileges of the user. (CAN-2005-1158)

Georgi Guninski discovered that the types of certain XPInstall
related JavaScript objects were not sufficiently validated when they
were called. This could be exploited by a malicious website to crash
Firefox or even execute arbitrary code with the privileges of the
user. (CAN-2005-1159)

Firefox did not properly verify the values of XML DOM nodes of web
pages. By tricking the user to perform a common action like clicking
on a link or opening the context menu, a malicious page could exploit
this to execute arbitrary JavaScript code with the full privileges of
the user. (CAN-2005-1160)");

  script_tag(name:"affected", value:"'mozilla, mozilla-firefox' package(s) on Ubuntu 5.04.");

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

if(release == "UBUNTU5.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libnspr-dev", ver:"1.7.6-1ubuntu2.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4", ver:"1.7.6-1ubuntu2.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss-dev", ver:"1.7.6-1ubuntu2.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3", ver:"1.7.6-1ubuntu2.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-browser", ver:"1.7.6-1ubuntu2.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-calendar", ver:"1.7.6-1ubuntu2.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-chatzilla", ver:"1.7.6-1ubuntu2.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-dev", ver:"1.7.6-1ubuntu2.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-dom-inspector", ver:"1.7.6-1ubuntu2.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-dev", ver:"1.0.2-0ubuntu5.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"1.0.2-0ubuntu5.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"1.0.2-0ubuntu5.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox", ver:"1.0.2-0ubuntu5.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-js-debugger", ver:"1.7.6-1ubuntu2.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-mailnews", ver:"1.7.6-1ubuntu2.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-psm", ver:"1.7.6-1ubuntu2.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla", ver:"1.7.6-1ubuntu2.1", rls:"UBUNTU5.04"))) {
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
