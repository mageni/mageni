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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0103");
  script_cve_id("CVE-2016-4570", "CVE-2016-4571");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-16 16:28:00 +0000 (Wed, 16 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2017-0103)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0103");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0103.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20593");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1334648");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-03/msg00081.html");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q2/276");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mxml' package(s) announced via the MGASA-2017-0103 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two stack exhaustion issues based on uncontrolled recursion were found in
mxml. A maliciously crafted xml file can cause the application to crash.

* Recursion using mxmlDelete at mxml-node.c:217 (reproducer is
 stack-exhaustion-1.xml CVE-2016-4570).

* Recursion using mxml_write_node at mxml-file.c:2739 (reproducer is
 stack-exhaustion-2.xml CVE-2016-4571).");

  script_tag(name:"affected", value:"'mxml' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64mxml-devel", rpm:"lib64mxml-devel~2.7~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mxml1", rpm:"lib64mxml1~2.7~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmxml-devel", rpm:"libmxml-devel~2.7~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmxml1", rpm:"libmxml1~2.7~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mxml", rpm:"mxml~2.7~6.1.mga5", rls:"MAGEIA5"))) {
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
