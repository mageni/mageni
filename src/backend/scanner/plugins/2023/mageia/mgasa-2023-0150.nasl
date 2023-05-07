# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0150");
  script_cve_id("CVE-2021-41556");
  script_tag(name:"creation_date", value:"2023-04-24 04:13:19 +0000 (Mon, 24 Apr 2023)");
  script_version("2023-04-24T10:19:26+0000");
  script_tag(name:"last_modification", value:"2023-04-24 10:19:26 +0000 (Mon, 24 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-05 22:30:00 +0000 (Fri, 05 Aug 2022)");

  script_name("Mageia: Security Advisory (MGASA-2023-0150)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0150");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0150.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30742");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/M3FQILX7UUEERSDPMZP3MKGTMY2E7ESU/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5NX6SWKNR7LNUXJROLGLSVD3ZEB4LUQY/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squirrel, supertux' package(s) announced via the MGASA-2023-0150 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"sqclass.cpp in Squirrel 3.1 allows an out-of-bounds read (in the core
interpreter) that can lead to Code Execution. If a victim executes an
attacker-controlled squirrel script, it is possible for the attacker to
break out of the squirrel script sandbox even if all dangerous
functionality such as File System functions has been disabled. An
attacker might abuse this bug to target (for example) Cloud services
that allow customization via SquirrelScripts, or distribute malware
through video games that embed a Squirrel Engine. (CVE-2021-41556)

supertux has been rebuilt as it uses a bundled copy of squirrel.");

  script_tag(name:"affected", value:"'squirrel, supertux' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64squirrel-devel", rpm:"lib64squirrel-devel~3.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64squirrel0", rpm:"lib64squirrel0~3.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsquirrel-devel", rpm:"libsquirrel-devel~3.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsquirrel0", rpm:"libsquirrel0~3.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squirrel", rpm:"squirrel~3.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"supertux", rpm:"supertux~0.6.2~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"supertux-data", rpm:"supertux-data~0.6.2~4.2.mga8", rls:"MAGEIA8"))) {
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
