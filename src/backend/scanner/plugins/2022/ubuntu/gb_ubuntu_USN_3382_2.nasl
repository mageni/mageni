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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2017.3382.2");
  script_cve_id("CVE-2016-10397", "CVE-2017-11143", "CVE-2017-11144", "CVE-2017-11145", "CVE-2017-11147", "CVE-2017-11628", "CVE-2017-9224", "CVE-2017-9226", "CVE-2017-9227", "CVE-2017-9228", "CVE-2017-9229");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 16:34:00 +0000 (Wed, 20 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-3382-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3382-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3382-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-3382-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3382-1 fixed several vulnerabilities in PHP. This update provides
the corresponding update for Ubuntu 12.04 ESM.

Original advisory details:

 It was discovered that the PHP URL parser incorrectly handled certain URI
 components. A remote attacker could possibly use this issue to bypass
 hostname-specific URL checks. (CVE-2016-10397)

 It was discovered that PHP incorrectly handled certain boolean parameters
 when unserializing data. A remote attacker could possibly use this issue to
 cause PHP to crash, resulting in a denial of service. (CVE-2017-11143)

 Sebastian Li, Wei Lei, Xie Xiaofei, and Liu Yang discovered that PHP
 incorrectly handled the OpenSSL sealing function. A remote attacker could
 possibly use this issue to cause PHP to crash, resulting in a denial of
 service. (CVE-2017-11144)

 Wei Lei and Liu Yang discovered that the PHP date extension incorrectly
 handled memory. A remote attacker could possibly use this issue to disclose
 sensitive information from the server. (CVE-2017-11145)

 It was discovered that PHP incorrectly handled certain PHAR archives. A
 remote attacker could use this issue to cause PHP to crash or disclose
 sensitive information. This issue only affected Ubuntu 14.04 LTS.
 (CVE-2017-11147)

 Wei Lei and Liu Yang discovered that PHP incorrectly handled parsing ini
 files. An attacker could possibly use this issue to cause PHP to crash,
 resulting in a denial of service. (CVE-2017-11628)

 It was discovered that PHP mbstring incorrectly handled certain regular
 expressions. A remote attacker could use this issue to cause PHP to crash,
 resulting in a denial of service, or possibly execute arbitrary code.
 (CVE-2017-9224, CVE-2017-9226, CVE-2017-9227, CVE-2017-9228, CVE-2017-9229)");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.10-1ubuntu3.28", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.10-1ubuntu3.28", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.10-1ubuntu3.28", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-fpm", ver:"5.3.10-1ubuntu3.28", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5", ver:"5.3.10-1ubuntu3.28", rls:"UBUNTU12.04 LTS"))) {
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
