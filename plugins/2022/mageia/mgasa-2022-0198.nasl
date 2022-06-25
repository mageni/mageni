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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0198");
  script_tag(name:"creation_date", value:"2022-05-23 04:32:41 +0000 (Mon, 23 May 2022)");
  script_version("2022-05-23T04:32:41+0000");
  script_tag(name:"last_modification", value:"2022-05-23 09:54:10 +0000 (Mon, 23 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2022-0198)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0198");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0198.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30442");
  script_xref(name:"URL", value:"https://www.nvidia.com/Download/driverResults.aspx/188877/en-us");
  script_xref(name:"URL", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5353");
  script_xref(name:"URL", value:"https://developer.blender.org/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ldetect-lst, nvidia-current' package(s) announced via the MGASA-2022-0198 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated nvidia-current packages fix security vulnerabilities:

NVIDIA GPU Display Driver contains a vulnerability in the kernel mode
layer, where an unprivileged regular user on the network can cause an
out-of-bounds write through a specially crafted shader, which may lead
to code execution, denial of service, escalation of privileges,
information disclosure, and data tampering. The scope of the impact may
extend to other components (CVE-2022-28181).

NVIDIA GPU Display Driver contains a vulnerability in the kernel mode
layer, where an unprivileged regular user can cause an out-of-bounds
read, which may lead to denial of service and information disclosure
(CVE-2022-28183).

NVIDIA GPU Display Driver contains a vulnerability in the kernel mode
layer (nvlddmkm.sys) handler for DxgkDdiEscape, where an unprivileged
regular user can access administrator- privileged registers, which may
lead to denial of service, information disclosure, and data tampering
(CVE-2022-28184).

NVIDIA GPU Display Driver contains a vulnerability in the ECC layer, where
an unprivileged regular user can cause an out-of-bounds write, which may
lead to denial of service and data tampering (CVE-2022-28185).

NVIDIA vGPU software contains a vulnerability in the Virtual GPU Manager
(nvidia.ko), where uncontrolled resource consumption can be triggered by
an unprivileged regular user, which may lead to denial of service
(CVE-2022-28191).

NVIDIA vGPU software contains a vulnerability in the Virtual GPU Manager
(nvidia.ko), where it may lead to a use-after-free, which in turn may
cause denial of service. This attack is complex to carry out because the
attacker needs to have control over freeing some host side resources out
of sequence, which requires elevated privileges (CVE-2022-28192).

This update also contains the following:

* Adds support for the following GPUs:
 GeForce RTX 3050
 GeForce RTX 3070 Ti Laptop GPU
 GeForce RTX 3080 Ti Laptop GPU
 GeForce RTX 3090 Ti
 RTX A500 Laptop GPU
 RTX A1000 Laptop GPU
 RTX A2000 8GB Laptop GPU
 RTX A3000 12GB Laptop GPU
 RTX A4500 Laptop GPU
 RTX A5500 Laptop GPU
 T550 Laptop GPU

* Fixes an issue where NvFBC was requesting Vulkan 1.0 while using Vulkan
 1.1 core features. This caused NvFBC to fail to initialize with Vulkan
 loader versions 1.3.204 or newer.

* Added an application profile to avoid an image corruption issue in
 Blender, as described at [link moved to references]");

  script_tag(name:"affected", value:"'ldetect-lst, nvidia-current' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"dkms-nvidia-current", rpm:"dkms-nvidia-current~470.129.06~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ldetect-lst", rpm:"ldetect-lst~0.6.26.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ldetect-lst-devel", rpm:"ldetect-lst-devel~0.6.26.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current", rpm:"nvidia-current~470.129.06~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-cuda-opencl", rpm:"nvidia-current-cuda-opencl~470.129.06~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-devel", rpm:"nvidia-current-devel~470.129.06~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-doc-html", rpm:"nvidia-current-doc-html~470.129.06~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-lib32", rpm:"nvidia-current-lib32~470.129.06~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-utils", rpm:"nvidia-current-utils~470.129.06~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-nvidia-current", rpm:"x11-driver-video-nvidia-current~470.129.06~1.mga8.nonfree", rls:"MAGEIA8"))) {
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
