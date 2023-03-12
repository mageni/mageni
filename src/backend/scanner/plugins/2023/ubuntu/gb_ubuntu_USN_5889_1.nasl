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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5889.1");
  script_cve_id("CVE-2019-6777", "CVE-2019-6990", "CVE-2019-6991", "CVE-2019-6992", "CVE-2019-7325", "CVE-2019-7326", "CVE-2019-7327", "CVE-2019-7328", "CVE-2019-7329", "CVE-2019-7330", "CVE-2019-7331", "CVE-2019-7332", "CVE-2022-29806");
  script_tag(name:"creation_date", value:"2023-02-28 04:10:38 +0000 (Tue, 28 Feb 2023)");
  script_version("2023-02-28T10:08:51+0000");
  script_tag(name:"last_modification", value:"2023-02-28 10:08:51 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-06 13:07:00 +0000 (Fri, 06 May 2022)");

  script_name("Ubuntu: Security Advisory (USN-5889-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5889-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5889-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zoneminder' package(s) announced via the USN-5889-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ZoneMinder was not properly sanitizing URL
parameters for certain views. An attacker could possibly use this issue to
perform a cross-site scripting (XSS) attack. This issue was only fixed in
Ubuntu 16.04 ESM. (CVE-2019-6777)

It was discovered that ZoneMinder was not properly sanitizing stored user
input later printed to the user in certain views. An attacker could
possibly use this issue to perform a cross-site scripting (XSS) attack.
This issue was only fixed in Ubuntu 16.04 ESM. (CVE-2019-6990,
CVE-2019-6992)

It was discovered that ZoneMinder was not properly limiting data size and
not properly performing bound checks when processing username and password
data, which could lead to a stack buffer overflow. An attacker could
possibly use this issue to bypass authentication, cause a denial of
service or execute arbitrary code. This issue was only fixed in Ubuntu
16.04 ESM. (CVE-2019-6991)

It was discovered that ZoneMinder was not properly defining and filtering
data that was appended to the webroot URL of a view. An attacker could
possibly use this issue to perform cross-site scripting (XSS) attacks.
This issue was only fixed in Ubuntu 16.04 ESM and Ubuntu 20.04 ESM.
(CVE-2019-7325, CVE-2019-7329)

It was discovered that ZoneMinder was not properly sanitizing stored user
input later printed to the user in certain views. An attacker could
possibly use this issue to perform a cross-site scripting (XSS) attack.
This issue was only fixed in Ubuntu 20.04 ESM. (CVE-2019-7326)

It was discovered that ZoneMinder was not properly sanitizing URL
parameters for certain views. An attacker could possibly use this issue to
perform a cross-site scripting (XSS) attack. This issue was only fixed in
Ubuntu 20.04 ESM. (CVE-2019-7327, CVE-2019-7328, CVE-2019-7330,
CVE-2019-7332)

It was discovered that ZoneMinder was not properly sanitizing user input
in the monitor editing view. An attacker could possibly use this issue to
perform a cross-site scripting (XSS) attack. This issue was only fixed in
Ubuntu 16.04 ESM and Ubuntu 20.04 ESM. (CVE-2019-7331)

It was discovered that ZoneMinder was not properly sanitizing data related
to file paths in a system. An attacker could possibly use this issue to
execute arbitrary code. (CVE-2022-29806)");

  script_tag(name:"affected", value:"'zoneminder' package(s) on Ubuntu 16.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"zoneminder", ver:"1.29.0+dfsg-1ubuntu2+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"zoneminder", ver:"1.32.3-2ubuntu2+esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"zoneminder", ver:"1.36.12+dfsg1-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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
