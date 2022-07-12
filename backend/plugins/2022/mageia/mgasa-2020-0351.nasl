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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0351");
  script_cve_id("CVE-2020-14928", "CVE-2020-16117");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 15:25:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0351)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0351");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0351.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26962");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2020/msg00131.html");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4725");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2281");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2309");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'evolution-data-server' package(s) announced via the MGASA-2020-0351 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"evolution-data-server (eds) through 3.36.3 has a STARTTLS buffering issue
that affects SMTP and POP3. When a server sends a 'begin TLS' response,
eds reads additional data and evaluates it in a TLS context, aka
'response injection'. (CVE-2020-14928)

In GNOME evolution-data-server before 3.35.91, a malicious server can crash
the mail client with a NULL pointer dereference by sending an invalid
(e.g., minimal) CAPABILITY line on a connection attempt.
This is related to imapx_free_capability and imapx_connect_to_server.
(CVE-2020-16117)");

  script_tag(name:"affected", value:"'evolution-data-server' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-data-server-tests", rpm:"evolution-data-server-tests~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64camel1.2_62", rpm:"lib64camel1.2_62~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ebackend1.2_10", rpm:"lib64ebackend1.2_10~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ebook-contacts1.2_2", rpm:"lib64ebook-contacts1.2_2~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ebook1.2_19", rpm:"lib64ebook1.2_19~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ecal1.2_19", rpm:"lib64ecal1.2_19~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64edata-book1.2_25", rpm:"lib64edata-book1.2_25~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64edata-cal1.2_29", rpm:"lib64edata-cal1.2_29~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64edataserver1.2-devel", rpm:"lib64edataserver1.2-devel~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64edataserver1.2_24", rpm:"lib64edataserver1.2_24~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64edataserverui1.2_2", rpm:"lib64edataserverui1.2_2~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64evolution-data-server-gir1.2", rpm:"lib64evolution-data-server-gir1.2~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcamel1.2_62", rpm:"libcamel1.2_62~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebackend1.2_10", rpm:"libebackend1.2_10~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebook-contacts1.2_2", rpm:"libebook-contacts1.2_2~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebook1.2_19", rpm:"libebook1.2_19~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecal1.2_19", rpm:"libecal1.2_19~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedata-book1.2_25", rpm:"libedata-book1.2_25~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedata-cal1.2_29", rpm:"libedata-cal1.2_29~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedataserver1.2-devel", rpm:"libedataserver1.2-devel~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedataserver1.2_24", rpm:"libedataserver1.2_24~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedataserverui1.2_2", rpm:"libedataserverui1.2_2~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libevolution-data-server-gir1.2", rpm:"libevolution-data-server-gir1.2~3.32.2~1.2.mga7", rls:"MAGEIA7"))) {
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
