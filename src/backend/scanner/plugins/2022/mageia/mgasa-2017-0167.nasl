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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0167");
  script_cve_id("CVE-2016-8649", "CVE-2017-5985");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-26 13:53:00 +0000 (Fri, 26 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0167)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0167");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0167.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20439");
  script_xref(name:"URL", value:"https://linuxcontainers.org/lxc/news/");
  script_xref(name:"URL", value:"https://www.ubuntu.com/usn/usn-3136-1/");
  script_xref(name:"URL", value:"https://www.ubuntu.com/usn/usn-3224-1/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19835");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lxc' package(s) announced via the MGASA-2017-0167 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Roman Fiedler discovered a directory traversal flaw in lxc-attach. An
attacker with access to an LXC container could exploit this flaw to
access files outside of the container (CVE-2016-8649).

Jann Horn discovered that LXC incorrectly verified permissions when
creating virtual network interfaces. A local attacker could possibly use
this issue to create virtual network interfaces in network namespaces
that they do not own (CVE-2017-5985).

The lxc package has been updated to version 1.0.10 to fix these issues
and other bugs.");

  script_tag(name:"affected", value:"'lxc' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64lxc-devel", rpm:"lib64lxc-devel~1.0.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64lxc1", rpm:"lib64lxc1~1.0.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblxc-devel", rpm:"liblxc-devel~1.0.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblxc1", rpm:"liblxc1~1.0.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc", rpm:"lxc~1.0.10~1.mga5", rls:"MAGEIA5"))) {
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
