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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2021.4843.1");
  script_cve_id("CVE-2014-9218", "CVE-2016-6609", "CVE-2016-6619", "CVE-2016-6630", "CVE-2016-9849", "CVE-2016-9866", "CVE-2017-1000014", "CVE-2017-1000015", "CVE-2017-18264", "CVE-2018-12581", "CVE-2018-19968", "CVE-2018-19970", "CVE-2018-7260", "CVE-2019-11768", "CVE-2019-12616", "CVE-2019-12922", "CVE-2019-19617", "CVE-2019-6798", "CVE-2020-26934", "CVE-2020-26935", "CVE-2020-5504");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-30 22:15:00 +0000 (Tue, 30 Mar 2021)");

  script_name("Ubuntu: Security Advisory (USN-4843-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4843-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4843-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpmyadmin' package(s) announced via the USN-4843-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Javier Nieto and Andres Rojas discovered that phpMyAdmin incorrectly
managed input in the form of passwords. An attacker could use this
vulnerability to cause a denial-of-service (DoS). This issue only
affected Ubuntu 14.04 ESM. (CVE-2014-9218)

Emanuel Bronshtein discovered that phpMyAdmin failed to properly sanitize
input in the form of database names in the PHP Array export feature.
An authenticated attacker could use this vulnerability to run arbitrary
PHP commands. This issue only affected Ubuntu 14.04 ESM and Ubuntu 16.04 ESM.
(CVE-2016-6609)

Emanuel Bronshtein discovered that phpMyAdmin failed to properly sanitize
input. An attacker could use this vulnerability to execute SQL injection
attacks. This issue only affected Ubuntu 14.04 ESM and Ubuntu 16.04 ESM.
(CVE-2016-6619)

Emanuel Bronshtein discovered that phpMyadmin failed to properly sanitize
input. An authenticated attacker could use this vulnerability to cause a
denial-of-service (DoS). This issue only affected Ubuntu 14.04 ESM and
Ubuntu 16.04 ESM. (CVE-2016-6630)

Emanuel Bronshtein discovered that phpMyAdmin failed to properly sanitize
input. An attacker could use this vulnerability to bypass AllowRoot
restrictions and deny rules for usernames. This issue only affected Ubuntu
14.04 ESM and Ubuntu 16.04 ESM. (CVE-2016-9849)

Emanuel Bronshtein discovered that phpMyAdmin would allow sensitive
information to be leaked when the argument separator in a URL was
not the default & value. An attacker could use this vulnerability to
obtain the CSRF token of a user. This issue only affected Ubuntu
14.04 ESM and Ubuntu 16.04 ESM. (CVE-2016-9866)

Isaac Bennetch discovered that phpMyAdmin was incorrectly restricting
user access due to the behavior of the substr function on some PHP
versions. An attacker could use this vulnerability to bypass login
restrictions established for users that have no password set. This
issue only affected Ubuntu 14.04 ESM. This issue only affected Ubuntu
14.04 ESM and Ubuntu 16.04 ESM. (CVE-2017-18264)

Emanuel Bronshtein discovered that phpMyAdmin failed to properly sanitize
input in the form of parameters sent during a table editing operation. An
attacker could use this vulnerability to trigger an endless recursion
and cause a denial-of-service (DoS). This issue only affected Ubuntu 14.04
ESM and Ubuntu 16.04 ESM. (CVE-2017-1000014)

Emanuel Bronshtein discovered that phpMyAdmin failed to properly sanitize
input used to generate a web page. An authenticated attacker could use this
vulnerability to execute CSS injection attacks. This issue only affected
Ubuntu 14.04 ESM and Ubuntu 16.04 ESM. (CVE-2017-1000015)

It was discovered that phpMyAdmin incorrectly handled certain input. An
attacker could use this vulnerability to execute a cross-site scripting (XSS)
attack via a crafted URL. This issue only affected Ubuntu 16.04 ESM.
(CVE-2018-7260)

It was discovered phpMyAdmin incorrectly ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:4.0.10-1ubuntu0.1+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:4.5.4.1-2ubuntu2.1+esm6", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:4.6.6-5ubuntu0.5+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:4.9.5+dfsg1-2ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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
