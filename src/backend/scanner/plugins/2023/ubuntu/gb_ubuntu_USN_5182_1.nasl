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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5182.1");
  script_cve_id("CVE-2020-12625", "CVE-2020-12626", "CVE-2020-12640", "CVE-2020-12641", "CVE-2020-13964", "CVE-2020-13965", "CVE-2020-15562", "CVE-2020-16145", "CVE-2020-35730", "CVE-2021-44025", "CVE-2021-44026", "CVE-2021-46144");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-23 00:08:00 +0000 (Tue, 23 Nov 2021)");

  script_name("Ubuntu: Security Advisory (USN-5182-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5182-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5182-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcube' package(s) announced via the USN-5182-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Roundcube Webmail allowed JavaScript code to be present
in the CDATA of an HTML message. A remote attacker could possibly use this
issue to execute a cross-site scripting (XSS) attack. This issue only affected
Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and Ubuntu 20.04 ESM. (CVE-2020-12625)

It was discovered that Roundcube Webmail incorrectly processed login and
logout POST requests. An attacker could possibly use this issue to launch a
cross-site request forgery (CSRF) attack and force an authenticated user to be
logged out. This issue only affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and
Ubuntu 20.04 ESM. (CVE-2020-12626)

It was discovered that Roundcube Webmail incorrectly processed new plugin names
in rcube_plugin_api.php. An attacker could possibly use this issue to obtain
sensitive information from local files or to execute arbitrary code.
This issue only affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and
Ubuntu 20.04 ESM. (CVE-2020-12640)

It was discovered that Roundcube Webmail did not sanitize shell metacharacters
recovered from variables in its configuration settings. An attacker could
possibly use this issue to execute arbitrary code in the server. This issue
only affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and Ubuntu 20.04 ESM.
(CVE-2020-12641)

It was discovered that Roundcube Webmail incorrectly sanitized characters in
the username template object. An attacker could possibly use this issue to
execute a cross-site scripting (XSS) attack. This issue only affected
Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and Ubuntu 20.04 ESM. (CVE-2020-13964)

It was discovered that Roundcube Webmail allowed preview of text/html content.
A remote attacker could possibly use this issue to send a malicious XML
attachment via an email message and execute a cross-site scripting (XSS)
attack. This issue only affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM
and Ubuntu 20.04 ESM. (CVE-2020-13965)

Andrea Cardaci discovered that Roundcube Webmail did not properly sanitize
HTML special characters when dealing with HTML messages that contained an SVG
element in the XML namespace. A remote attacker could possibly use this issue
to execute a cross-site scripting (XSS) attack. This issue only affected
Ubuntu 18.04 ESM and Ubuntu 20.04 ESM. (CVE-2020-15562)

Lukasz Pilorz discovered that Roundcube Webmail did not properly sanitize HTML
special characters when dealing with HTML messages that contained SVG
documents. A remote attacker could possibly use this issue to execute a
cross-site scripting (XSS) attack. This issue only affected Ubuntu 18.04 ESM
and Ubuntu 20.04 ESM. (CVE-2020-16145)

Alex Birnberg discovered that Roundcube Webmail incorrectly sanitized
characters in plain text e-mail messages that included link reference
elements. A remote attacker could possibly use this issue to execute a
cross-site scripting (XSS) attack. This issue only affected Ubuntu 16.04 ESM,
Ubuntu 18.04 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'roundcube' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-core", ver:"1.2~beta+dfsg.1-0ubuntu1+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube", ver:"1.2~beta+dfsg.1-0ubuntu1+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-core", ver:"1.3.6+dfsg.1-1ubuntu0.1~esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube", ver:"1.3.6+dfsg.1-1ubuntu0.1~esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-core", ver:"1.4.3+dfsg.1-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube", ver:"1.4.3+dfsg.1-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-core", ver:"1.5.0+dfsg.1-2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube", ver:"1.5.0+dfsg.1-2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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
