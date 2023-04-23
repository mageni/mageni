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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3390");
  script_cve_id("CVE-2019-15132", "CVE-2020-15803", "CVE-2021-27927", "CVE-2022-24349", "CVE-2022-24917", "CVE-2022-24919", "CVE-2022-35229", "CVE-2022-35230");
  script_tag(name:"creation_date", value:"2023-04-13 04:27:00 +0000 (Thu, 13 Apr 2023)");
  script_version("2023-04-13T10:09:33+0000");
  script_tag(name:"last_modification", value:"2023-04-13 10:09:33 +0000 (Thu, 13 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-29 18:15:00 +0000 (Mon, 29 Mar 2021)");

  script_name("Debian: Security Advisory (DLA-3390)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3390");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3390");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/zabbix");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'zabbix' package(s) announced via the DLA-3390 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in zabbix, a network monitoring solution, potentially allowing User Enumeration, Cross-Site-Scripting or Cross-Site Request Forgery.

CVE-2019-15132

Zabbix through 4.4.0alpha1 allows User Enumeration. With login requests, it is possible to enumerate application usernames based on the variability of server responses (e.g., the Login name or password is incorrect and No permissions for system access messages, or just blocking for a number of seconds). This affects both api_jsonrpc.php and index.php.

CVE-2020-15803

Zabbix before 3.0.32rc1, 4.x before 4.0.22rc1, 4.1.x through 4.4.x before 4.4.10rc1, and 5.x before 5.0.2rc1 allows stored XSS in the URL Widget.

CVE-2021-27927

In Zabbix from 4.0.x before 4.0.28rc1, 5.0.0alpha1 before 5.0.10rc1, 5.2.x before 5.2.6rc1, and 5.4.0alpha1 before 5.4.0beta2, the CControllerAuthenticationUpdate controller lacks a CSRF protection mechanism. The code inside this controller calls diableSIDValidation inside the init() method. An attacker doesn't have to know Zabbix user login credentials, but has to know the correct Zabbix URL and contact information of an existing user with sufficient privileges.

CVE-2022-24349

An authenticated user can create a link with reflected XSS payload for actions' pages, and send it to other users. Malicious code has access to all the same objects as the rest of the web page and can make arbitrary modifications to the contents of the page being displayed to a victim. This attack can be implemented with the help of social engineering and expiration of a number of factors - an attacker should have authorized access to the Zabbix Frontend and allowed network connection between a malicious server and victim's computer, understand attacked infrastructure, be recognized by the victim as a trustee and use trusted communication channel.

CVE-2022-24917

An authenticated user can create a link with reflected Javascript code inside it for services' page and send it to other users. The payload can be executed only with a known CSRF token value of the victim, which is changed periodically and is difficult to predict. Malicious code has access to all the same objects as the rest of the web page and can make arbitrary modifications to the contents of the page being displayed to a victim during social engineering attacks.

CVE-2022-24919

An authenticated user can create a link with reflected Javascript code inside it for graphs' page and send it to other users. The payload can be executed only with a known CSRF token value of the victim, which is changed periodically and is difficult to predict. Malicious code has access to all the same objects as the rest of the web page and can make arbitrary modifications to the contents of the page being displayed to a victim during social engineering attacks.

CVE-2022-35229

An authenticated user can create a link with ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'zabbix' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-agent", ver:"1:4.0.4+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-frontend-php", ver:"1:4.0.4+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-java-gateway", ver:"1:4.0.4+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-mysql", ver:"1:4.0.4+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-pgsql", ver:"1:4.0.4+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-sqlite3", ver:"1:4.0.4+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-server-mysql", ver:"1:4.0.4+dfsg-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-server-pgsql", ver:"1:4.0.4+dfsg-1+deb10u1", rls:"DEB10"))) {
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
