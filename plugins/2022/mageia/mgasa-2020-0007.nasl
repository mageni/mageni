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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0007");
  script_cve_id("CVE-2019-10143", "CVE-2019-13456", "CVE-2019-17185");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-26 18:15:00 +0000 (Sun, 26 Apr 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0007)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0007");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0007.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25907");
  script_xref(name:"URL", value:"https://github.com/FreeRADIUS/freeradius-server/releases/tag/release_3_0_20");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/TKODLHHUOVAYENTBP4D3N25ST3Q6LJBP/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/USTITI4A3TVUX3SGO7TJCJ4WWFBZFWLZ/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeradius' package(s) announced via the MGASA-2020-0007 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated freeradius packages fix security vulnerabilities:

It was discovered freeradius does not correctly configure logrotate,
allowing a local attacker who already has control of the radiusd user to
escalate his privileges to root, by tricking logrotate into writing a
radiusd-writable file to a directory normally inaccessible by the radiusd
 user (CVE-2019-10143).

An information leak was discovered in the implementation of EAP-pwd in
freeradius. An attacker could initiate several EAP-pwd handshakes to leak
information, which can then be used to recover the user's WiFi password by
performing dictionary and brute-force attacks (CVE-2019-13456).

Denial of service issues due to multithreaded BN_CTX access
(CVE-2019-17185).");

  script_tag(name:"affected", value:"'freeradius' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"freeradius", rpm:"freeradius~3.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-krb5", rpm:"freeradius-krb5~3.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-ldap", rpm:"freeradius-ldap~3.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-mysql", rpm:"freeradius-mysql~3.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-postgresql", rpm:"freeradius-postgresql~3.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-sqlite", rpm:"freeradius-sqlite~3.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-unixODBC", rpm:"freeradius-unixODBC~3.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-yubikey", rpm:"freeradius-yubikey~3.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freeradius-devel", rpm:"lib64freeradius-devel~3.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freeradius1", rpm:"lib64freeradius1~3.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreeradius-devel", rpm:"libfreeradius-devel~3.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreeradius1", rpm:"libfreeradius1~3.0.20~1.mga7", rls:"MAGEIA7"))) {
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
