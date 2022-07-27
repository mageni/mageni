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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0308");
  script_cve_id("CVE-2017-6594");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-12 17:50:00 +0000 (Thu, 12 Aug 2021)");

  script_name("Mageia: Security Advisory (MGASA-2017-0308)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0308");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0308.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21550");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-08/msg00062.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'heimdal' package(s) announced via the MGASA-2017-0308 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Transit path validation inadvertently caused the previous hop realm to
not be added to the transit path of issued tickets. This may, in some
cases, enable bypass of capath policy in Heimdal versions 1.5 through
7.2 (CVE-2017-6594).

Note, this may break sites that rely on the bug. With the bug some
incomplete [capaths] worked, that should not have. These may now break
authentication in some cross-realm configurations.");

  script_tag(name:"affected", value:"'heimdal' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"heimdal", rpm:"heimdal~1.5.3~6.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heimdal-daemons", rpm:"heimdal-daemons~1.5.3~6.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heimdal-devel", rpm:"heimdal-devel~1.5.3~6.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heimdal-devel-doc", rpm:"heimdal-devel-doc~1.5.3~6.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heimdal-ftp", rpm:"heimdal-ftp~1.5.3~6.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heimdal-ftpd", rpm:"heimdal-ftpd~1.5.3~6.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heimdal-libs", rpm:"heimdal-libs~1.5.3~6.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heimdal-rsh", rpm:"heimdal-rsh~1.5.3~6.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heimdal-rshd", rpm:"heimdal-rshd~1.5.3~6.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heimdal-server", rpm:"heimdal-server~1.5.3~6.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heimdal-telnet", rpm:"heimdal-telnet~1.5.3~6.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heimdal-telnetd", rpm:"heimdal-telnetd~1.5.3~6.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heimdal-workstation", rpm:"heimdal-workstation~1.5.3~6.2.mga5", rls:"MAGEIA5"))) {
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
