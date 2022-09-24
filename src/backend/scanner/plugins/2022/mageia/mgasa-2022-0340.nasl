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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0340");
  script_cve_id("CVE-2022-25647");
  script_tag(name:"creation_date", value:"2022-09-22 04:40:55 +0000 (Thu, 22 Sep 2022)");
  script_version("2022-09-22T10:44:54+0000");
  script_tag(name:"last_modification", value:"2022-09-22 10:44:54 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-11 16:18:00 +0000 (Wed, 11 May 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0340)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0340");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0340.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30541");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GA6JLF7SGHTXIPP5ONV5N4ECGGCVIYYM/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3100");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5227");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'google-gson' package(s) announced via the MGASA-2022-0340 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The package com.google.code.gson:gson before 2.8.9 are vulnerable to
Deserialization of Untrusted Data via the writeReplace() method in
internal classes, which may lead to DoS attacks. (CVE-2022-25647)");

  script_tag(name:"affected", value:"'google-gson' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"google-gson", rpm:"google-gson~2.8.6~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"google-gson-javadoc", rpm:"google-gson-javadoc~2.8.6~1.1.mga8", rls:"MAGEIA8"))) {
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
