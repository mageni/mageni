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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0197");
  script_tag(name:"creation_date", value:"2022-05-23 04:32:41 +0000 (Mon, 23 May 2022)");
  script_version("2022-05-23T04:32:41+0000");
  script_tag(name:"last_modification", value:"2022-05-23 09:54:10 +0000 (Mon, 23 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2022-0197)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0197");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0197.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30441");
  script_xref(name:"URL", value:"https://www.nvidia.com/Download/driverResults.aspx/188601/en-us");
  script_xref(name:"URL", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5353");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nvidia390' package(s) announced via the MGASA-2022-0197 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated nvidia390 packages fix security vulnerabilities:

NVIDIA GPU Display Driver contains a vulnerability in the kernel mode
layer, where an unprivileged regular user on the network can cause an
out-of-bounds write through a specially crafted shader, which may lead
to code execution, denial of service, escalation of privileges,
information disclosure, and data tampering. The scope of the impact may
extend to other components (CVE-2022-28181).

NVIDIA GPU Display Driver contains a vulnerability in the ECC layer, where
an unprivileged regular user can cause an out-of-bounds write, which may
lead to denial of service and data tampering (CVE-2022-28185).

This driver also adds official support for kernel 5.17+ series.");

  script_tag(name:"affected", value:"'nvidia390' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"dkms-nvidia390", rpm:"dkms-nvidia390~390.151~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia390", rpm:"nvidia390~390.151~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia390-cuda-opencl", rpm:"nvidia390-cuda-opencl~390.151~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia390-devel", rpm:"nvidia390-devel~390.151~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia390-doc-html", rpm:"nvidia390-doc-html~390.151~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia390-lib32", rpm:"nvidia390-lib32~390.151~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia390-utils", rpm:"nvidia390-utils~390.151~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-nvidia390", rpm:"x11-driver-video-nvidia390~390.151~1.mga8.nonfree", rls:"MAGEIA8"))) {
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
