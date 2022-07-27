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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0237");
  script_cve_id("CVE-2020-25097", "CVE-2021-28651", "CVE-2021-28652", "CVE-2021-28662", "CVE-2021-31806", "CVE-2021-31807", "CVE-2021-31808", "CVE-2021-33620");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 11:15:00 +0000 (Wed, 26 May 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0237)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0237");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0237.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28799");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-jvf6-h9gj-pmj6");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-ch36-9jhx-phm4");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-m47m-9hvw-7447");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-jjq6-mh2h-g39h");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-pxwq-f3qr-w2xf");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-572g-rvwr-6c7f");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/commit/fa47a3bc4d382e28e7235d08750401b910e4b13a");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/commit/648729b05673c6166c5d91c6ee4cda30cc164839");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2021:1135");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4981-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid, squid' package(s) announced via the MGASA-2021-0237 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated squid packages fix security vulnerabilities:

Due to improper input validation Squid is vulnerable to an HTTP Request
Smuggling attack. This problem allows a trusted client to perform HTTP
Request Smuggling and access services otherwise forbidden by Squid
security controls (CVE-2020-25097).

Joshua Rogers discovered that Squid incorrectly handled requests with the
urn: scheme. A remote attacker could possibly use this issue to causeSquid
to consume resources, leading to a denial of service (CVE-2021-28651).

Joshua Rogers discovered that Squid incorrectly handled requests to the Cache
Manager API. A remote attacker with access privileges could possibly use this
issue to cause Squid to consume resources, leading to a denial of service
(CVE-2021-28652).

Joshua Rogers discovered that Squid incorrectly handled certain response
headers. A remote attacker could possibly use this issue to cause Squid to
crash, resulting in a denial of service (CVE-2021-28662).

Joshua Rogers discovered that Squid incorrectly handled range request
processing. A remote attacker could possibly use this issue to cause Squid to
crash, resulting in a denial of service (CVE-2021-31806, CVE-2021-31807,
CVE-2021-31808).

Joshua Rogers discovered that Squid incorrectly handled certain HTTP
responses. A remote attacker could possibly use this issue to cause Squid to
crash, resulting in a denial of service (CVE-2021-33620).

The squid package has been updated to version 4.15, fixing these issues and
other bugs.");

  script_tag(name:"affected", value:"'squid, squid' package(s) on Mageia 7, Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~4.15~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-cachemgr", rpm:"squid-cachemgr~4.15~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~4.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-cachemgr", rpm:"squid-cachemgr~4.15~1.mga8", rls:"MAGEIA8"))) {
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
