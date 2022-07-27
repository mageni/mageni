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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0442");
  script_cve_id("CVE-2014-6273");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-08 15:22:00 +0000 (Wed, 08 Jan 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0442)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0442");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0442.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14112");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2353-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apt, apt' package(s) announced via the MGASA-2014-0442 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Google Security Team discovered a buffer overflow vulnerability in the
HTTP transport code in apt-get. An attacker able to man-in-the-middle a HTTP
request to an apt repository can trigger the buffer overflow, leading to a
crash of the 'http' apt method binary, or potentially to arbitrary code
execution (CVE-2014-6273).

Also fixed is parsing of Mageia package index 'synthesis' files with lines
longer than 64k characters. This is necessary for upgrading to the 'cauldron'
development distro that will become Mageia 5. Note however that upgrading from
Mageia 3 to Mageia 5 will not be supported.");

  script_tag(name:"affected", value:"'apt, apt' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"apt", rpm:"apt~0.5.15lorg3.94~9.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apt-common", rpm:"apt-common~0.5.15lorg3.94~9.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64apt-pkg4", rpm:"lib64apt-pkg4~0.5.15lorg3.94~9.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64apt-pkg4-devel", rpm:"lib64apt-pkg4-devel~0.5.15lorg3.94~9.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapt-pkg4", rpm:"libapt-pkg4~0.5.15lorg3.94~9.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapt-pkg4-devel", rpm:"libapt-pkg4-devel~0.5.15lorg3.94~9.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"apt", rpm:"apt~0.5.15lorg3.94~11.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apt-common", rpm:"apt-common~0.5.15lorg3.94~11.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64apt-pkg-devel", rpm:"lib64apt-pkg-devel~0.5.15lorg3.94~11.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64apt-pkg4", rpm:"lib64apt-pkg4~0.5.15lorg3.94~11.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapt-pkg-devel", rpm:"libapt-pkg-devel~0.5.15lorg3.94~11.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapt-pkg4", rpm:"libapt-pkg4~0.5.15lorg3.94~11.2.mga4", rls:"MAGEIA4"))) {
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
