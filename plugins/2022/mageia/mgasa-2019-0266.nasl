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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0266");
  script_cve_id("CVE-2019-12525", "CVE-2019-12527", "CVE-2019-12529", "CVE-2019-12854", "CVE-2019-13345");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-11 00:15:00 +0000 (Sat, 11 Jul 2020)");

  script_name("Mageia: Security Advisory (MGASA-2019-0266)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0266");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0266.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25110");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/4059-1/");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/4065-1/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4507");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the MGASA-2019-0266 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated squid packages fix security vulnerabilities:

It was discovered that Squid incorrectly handled Digest authentication.
A remote attacker could possibly use this issue to cause Squid to crash,
resulting in a denial of service (CVE-2019-12525).

It was discovered that Squid incorrectly handled Basic authentication.
A remote attacker could use this issue to cause Squid to crash, resulting
in a denial of service, or possibly execute arbitrary code (CVE-2019-12527).

It was discovered that Squid incorrectly handled Basic authentication.
A remote attacker could possibly use this issue to cause Squid to crash,
resulting in a denial of service (CVE-2019-12529).

Due to incorrect string termination, Squid cachemgr.cgi 4.0 through 4.7
may access unallocated memory. On systems with memory access protections,
this can cause the CGI process to terminate unexpectedly, resulting in a
denial of service for all clients using it (CVE-2019-12854).

It was discovered that Squid incorrectly handled the cachemgr.cgi web
module. A remote attacker could possibly use this issue to conduct
cross-site scripting (XSS) attacks (CVE-2019-13345).

The squid package has been updated to version 4.8, fixing these issues and
other bugs.");

  script_tag(name:"affected", value:"'squid' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~4.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-cachemgr", rpm:"squid-cachemgr~4.8~1.mga7", rls:"MAGEIA7"))) {
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
