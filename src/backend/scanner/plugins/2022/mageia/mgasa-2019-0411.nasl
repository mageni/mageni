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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0411");
  script_cve_id("CVE-2018-1054", "CVE-2018-10871", "CVE-2019-14824", "CVE-2019-3883");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-17 01:29:00 +0000 (Tue, 17 Jul 2018)");

  script_name("Mageia: Security Advisory (MGASA-2019-0411)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0411");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0411.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25824");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25709");
  script_xref(name:"URL", value:"http://lists.suse.com/pipermail/sle-security-updates/2019-August/005817.html");
  script_xref(name:"URL", value:"https://directory.fedoraproject.org/docs/389ds/releases/release-1-4-0-31.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base' package(s) announced via the MGASA-2019-0411 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"he updated packages fix security vulnerabilities and a packaging problem:

An out-of-bounds memory read flaw was found in the way 389-ds-base handled
certain LDAP search filters, affecting all versions including 1.4.x. A
remote, unauthenticated attacker could potentially use this flaw to make
ns-slapd crash via a specially crafted LDAP request, thus resulting in
denial of service. (CVE-2018-1054)

389-ds-base before versions 1.3.8.5, 1.4.0.12 is vulnerable to a Cleartext
Storage of Sensitive Information. By default, when the Replica and/or
retroChangeLog plugins are enabled, 389-ds-base stores passwords in
plaintext format in their respective changelog files. An attacker with
sufficiently high privileges, such as root or Directory Manager, can
query these files in order to retrieve plaintext passwords.
(CVE-2018-10871)

In 389-ds-base up to version 1.4.1.2, requests are handled by workers
threads. Each sockets will be waited by the worker for at most
'ioblocktimeout' seconds. However this timeout applies only for un-
encrypted requests. Connections using SSL/TLS are not taking this timeout
into account during reads, and may hang longer.An unauthenticated attacker
could repeatedly create hanging LDAP requests to hang all the workers,
resulting in a Denial of Service. (CVE-2019-3883)

A flaw was found in the 'deref' plugin of 389-ds-base where it could use
the 'search' permission to display attribute values. In some configurations,
this could allow an authenticated attacker to view private attributes, such
as password hashes. (CVE-2019-14824)

There were conflicts between files from svrcore and 389-ds-base which
prevented the installation of 389-ds (mga#25709)");

  script_tag(name:"affected", value:"'389-ds-base' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.4.0.26~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-snmp", rpm:"389-ds-base-snmp~1.4.0.26~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-389-ds", rpm:"cockpit-389-ds~1.4.0.26~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib389-ds-base-devel", rpm:"lib389-ds-base-devel~1.4.0.26~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib389-ds-base0", rpm:"lib389-ds-base0~1.4.0.26~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64389-ds-base-devel", rpm:"lib64389-ds-base-devel~1.4.0.26~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64389-ds-base0", rpm:"lib64389-ds-base0~1.4.0.26~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64svrcore-devel", rpm:"lib64svrcore-devel~1.4.0.26~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64svrcore0", rpm:"lib64svrcore0~1.4.0.26~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvrcore-devel", rpm:"libsvrcore-devel~1.4.0.26~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvrcore0", rpm:"libsvrcore0~1.4.0.26~1.1.mga7", rls:"MAGEIA7"))) {
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
