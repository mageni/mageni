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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.149.3");
  script_cve_id("CVE-2004-1156", "CVE-2004-1381", "CVE-2005-0141", "CVE-2005-0142", "CVE-2005-0143", "CVE-2005-0144", "CVE-2005-0145", "CVE-2005-0146", "CVE-2005-0147", "CVE-2005-0150", "CVE-2005-0230", "CVE-2005-0231", "CVE-2005-0232", "CVE-2005-0233", "CVE-2005-0255", "CVE-2005-0399", "CVE-2005-0401", "CVE-2005-0402", "CVE-2005-0578", "CVE-2005-0584", "CVE-2005-0585", "CVE-2005-0586", "CVE-2005-0587", "CVE-2005-0588", "CVE-2005-0589", "CVE-2005-0590", "CVE-2005-0591", "CVE-2005-0592", "CVE-2005-0593", "CVE-2005-0752", "CVE-2005-0989", "CVE-2005-1153", "CVE-2005-1154", "CVE-2005-1155", "CVE-2005-1156", "CVE-2005-1157", "CVE-2005-1158", "CVE-2005-1159", "CVE-2005-1160", "CVE-2005-1531", "CVE-2005-1532", "CVE-2005-1937", "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2262", "CVE-2005-2263", "CVE-2005-2264", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2267", "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-149-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU4\.10");

  script_xref(name:"Advisory-ID", value:"USN-149-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-149-3");
  script_xref(name:"URL", value:"http://www.ubuntulinux.org/support/documentation/usn/usn-149-1");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-firefox, mozilla-firefox-locale-ca, mozilla-firefox-locale-de, mozilla-firefox-locale-es, mozilla-firefox-locale-fr, mozilla-firefox-locale-it, mozilla-firefox-locale-ja, mozilla-firefox-locale-nb, mozilla-firefox-locale-pl, mozilla-firefox-locale-tr, mozilla-firefox-locale-uk' package(s) announced via the USN-149-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-149-1 fixed some vulnerabilities in the Ubuntu 5.04 (Hoary
Hedgehog) version of Firefox. The version shipped with Ubuntu 4.10
(Warty Warthog) is also vulnerable to these flaws, so it needs to be
upgraded as well. Please see

 [link moved to references]

for the original advisory.

This update also fixes several older vulnerabilities, Some of them
could be exploited to execute arbitrary code with full user privileges
if the user visited a malicious web site. (MFSA-2005-01 to
MFSA-2005-44, please see the following web site for details:
[link moved to references])");

  script_tag(name:"affected", value:"'mozilla-firefox, mozilla-firefox-locale-ca, mozilla-firefox-locale-de, mozilla-firefox-locale-es, mozilla-firefox-locale-fr, mozilla-firefox-locale-it, mozilla-firefox-locale-ja, mozilla-firefox-locale-nb, mozilla-firefox-locale-pl, mozilla-firefox-locale-tr, mozilla-firefox-locale-uk' package(s) on Ubuntu 4.10.");

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

if(release == "UBUNTU4.10") {

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"1.0.6-0ubuntu0.0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-locale-ca", ver:"1.0-0ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-locale-de", ver:"1.0-0ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-locale-es", ver:"1.0-0ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-locale-fr", ver:"1.0-0ubuntu0.2", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-locale-it", ver:"1.0-0ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-locale-ja", ver:"1.0-0ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-locale-nb", ver:"1.0-0ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-locale-pl", ver:"1.0-0ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-locale-tr", ver:"1.0-0ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-locale-uk", ver:"1.0-0ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox", ver:"1.0.6-0ubuntu0.0.1", rls:"UBUNTU4.10"))) {
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
