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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0048");
  script_cve_id("CVE-2019-20919", "CVE-2020-14392", "CVE-2020-14393");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-28 16:15:00 +0000 (Mon, 28 Sep 2020)");

  script_name("Mageia: Security Advisory (MGASA-2021-0048)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0048");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0048.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27304");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4503-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2020-09/msg00067.html");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4534-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/JXLKODJ7B57GITDEZZXNSHPK4VBYXYHR/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-DBI' package(s) announced via the MGASA-2021-0048 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in the DBI module before 1.643 for Perl. The
hv_fetch() documentation requires checking for NULL and the code does that.
But, shortly thereafter, it calls SvOK(profile), causing a NULL pointer
dereference. (CVE-2019-20919).

An untrusted pointer dereference flaw was found in Perl-DBI < 1.643. A local
attacker who is able to manipulate calls to dbd_db_login6_sv() could cause
memory corruption, affecting the service's availability. (CVE-2020-14392).

A buffer overflow was found in perl-DBI < 1.643 in DBI.xs. A local attacker
who is able to supply a string longer than 300 characters could cause an
out-of-bounds write, affecting the availability of the service or integrity
of data. (CVE-2020-14393).");

  script_tag(name:"affected", value:"'perl-DBI' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl-DBI", rpm:"perl-DBI~1.642.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-DBI-ProfileDumper-Apache", rpm:"perl-DBI-ProfileDumper-Apache~1.642.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-DBI-proxy", rpm:"perl-DBI-proxy~1.642.0~1.1.mga7", rls:"MAGEIA7"))) {
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
