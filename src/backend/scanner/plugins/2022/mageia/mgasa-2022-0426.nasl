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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0426");
  script_cve_id("CVE-2022-43995");
  script_tag(name:"creation_date", value:"2022-11-18 04:13:30 +0000 (Fri, 18 Nov 2022)");
  script_version("2022-11-18T04:13:30+0000");
  script_tag(name:"last_modification", value:"2022-11-18 04:13:30 +0000 (Fri, 18 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-03 03:35:00 +0000 (Thu, 03 Nov 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0426)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0426");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0426.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31089");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-November/012820.html");
  script_xref(name:"URL", value:"https://www.sudo.ws/releases/stable/#1.9.12p1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the MGASA-2022-0426 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sudo 1.8.0 through 1.9.12, with the crypt() password backend, contains a
plugins/sudoers/auth/passwd.c array-out-of-bounds error that can result in
a heap-based buffer over-read. This can be triggered by arbitrary local
users with access to Sudo by entering a password of seven characters or
fewer. The impact could vary depending on the system libraries, compiler,
and processor architecture. (CVE-2022-43995)");

  script_tag(name:"affected", value:"'sudo' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.9.5p2~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-devel", rpm:"sudo-devel~1.9.5p2~2.1.mga8", rls:"MAGEIA8"))) {
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
