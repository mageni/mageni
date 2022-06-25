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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0013");
  script_cve_id("CVE-2016-7382", "CVE-2016-7389", "CVE-2016-8826");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-20 02:59:00 +0000 (Fri, 20 Jan 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0013)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0013");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0013.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19993");
  script_xref(name:"URL", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/4246");
  script_xref(name:"URL", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/4278");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nvidia304, nvidia340' package(s) announced via the MGASA-2017-0013 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This proprietary nvidia340 and nvidia304 driver update fixes the
following security issues:

NVIDIA GPU Display Driver contains a vulnerability in the kernel mode
layer (nvidia.ko) handler where a missing permissions check may allow
users to gain access to arbitrary physical memory, leading to an
escalation of privileges (CVE-2016-7382).

NVIDIA GPU Display Driver on Linux contains a vulnerability in the
kernel mode layer (nvidia.ko) handler for mmap() where improper input
validation may allow users to gain access to arbitrary physical memory,
leading to an escalation of privileges (CVE-2016-7389).

NVIDIA GPU Display Driver contains a vulnerability in the kernel mode
layer (nvidia.ko) where a user can cause a GPU interrupt storm, leading
to a denial of service (CVE-2016-8826).");

  script_tag(name:"affected", value:"'nvidia304, nvidia340' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"dkms-nvidia304", rpm:"dkms-nvidia304~304.134~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-nvidia340", rpm:"dkms-nvidia340~340.101~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304", rpm:"nvidia304~304.134~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-cuda-opencl", rpm:"nvidia304-cuda-opencl~304.134~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-devel", rpm:"nvidia304-devel~304.134~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-doc-html", rpm:"nvidia304-doc-html~304.134~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia340", rpm:"nvidia340~340.101~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia340-cuda-opencl", rpm:"nvidia340-cuda-opencl~340.101~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia340-devel", rpm:"nvidia340-devel~340.101~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia340-doc-html", rpm:"nvidia340-doc-html~340.101~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-nvidia304", rpm:"x11-driver-video-nvidia304~304.134~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-nvidia340", rpm:"x11-driver-video-nvidia340~340.101~1.mga5.nonfree", rls:"MAGEIA5"))) {
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
