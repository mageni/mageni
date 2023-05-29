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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3418");
  script_cve_id("CVE-2022-34670", "CVE-2022-34674", "CVE-2022-34675", "CVE-2022-34677", "CVE-2022-34680", "CVE-2022-42257", "CVE-2022-42258", "CVE-2022-42259");
  script_tag(name:"creation_date", value:"2023-05-12 04:20:36 +0000 (Fri, 12 May 2023)");
  script_version("2023-05-12T09:09:03+0000");
  script_tag(name:"last_modification", value:"2023-05-12 09:09:03 +0000 (Fri, 12 May 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-11 20:14:00 +0000 (Wed, 11 Jan 2023)");

  script_name("Debian: Security Advisory (DLA-3418)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3418");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3418");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/nvidia-graphics-drivers-legacy-390xx");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nvidia-graphics-drivers-legacy-390xx' package(s) announced via the DLA-3418 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"NVIDIA has released a software security update for the NVIDIA GPU Display Driver R390 linux driver branch. This update addresses issues that may lead to denial of service, escalation of privileges, information disclosure, data tampering or undefined behavior.


CVE-2022-34670

NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an unprivileged regular user can cause truncation errors when casting a primitive to a primitive of smaller size causes data to be lost in the conversion, which may lead to denial of service or information disclosure.

CVE-2022-34674

NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where a helper function maps more physical pages than were requested, which may lead to undefined behavior or an information leak.

CVE-2022-34675

NVIDIA Display Driver for Linux contains a vulnerability in the Virtual GPU Manager, where it does not check the return value from a null-pointer dereference, which may lead to denial of service.

CVE-2022-34677

NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an unprivileged regular user can cause an integer to be truncated, which may lead to denial of service or data tampering.

CVE-2022-34680

NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an integer truncation can lead to an out-of-bounds read, which may lead to denial of service.

CVE-2022-42257

NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where an integer overflow may lead to information disclosure, data tampering or denial of service.

CVE-2022-42258

NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where an integer overflow may lead to denial of service, data tampering, or information disclosure.

CVE-2022-42259

NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where an integer overflow may lead to denial of service.

For Debian 10 buster, these problems have been fixed in version 390.157-1~deb10u1.

We recommend that you upgrade your nvidia-graphics-drivers-legacy-390xx packages.

For the detailed security status of nvidia-graphics-drivers-legacy-390xx please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'nvidia-graphics-drivers-legacy-390xx' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libegl-nvidia-legacy-390xx0", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libegl1-nvidia-legacy-390xx", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgl1-nvidia-legacy-390xx-glvnd-glx", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgl1-nvidia-legacy-390xx-glx", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgles-nvidia-legacy-390xx1", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgles-nvidia-legacy-390xx2", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglx-nvidia-legacy-390xx0", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnvidia-legacy-390xx-cfg1", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnvidia-legacy-390xx-compiler", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnvidia-legacy-390xx-cuda1-i386", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnvidia-legacy-390xx-cuda1", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnvidia-legacy-390xx-eglcore", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnvidia-legacy-390xx-encode1", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnvidia-legacy-390xx-fatbinaryloader", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnvidia-legacy-390xx-fbc1", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnvidia-legacy-390xx-glcore", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnvidia-legacy-390xx-ifr1", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnvidia-legacy-390xx-ml1", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnvidia-legacy-390xx-nvcuvid1", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnvidia-legacy-390xx-ptxjitcompiler1", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-legacy-390xx-alternative", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-legacy-390xx-driver-bin", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-legacy-390xx-driver-libs-i386", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-legacy-390xx-driver-libs-nonglvnd-i386", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-legacy-390xx-driver-libs-nonglvnd", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-legacy-390xx-driver-libs", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-legacy-390xx-driver", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-legacy-390xx-egl-icd", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-legacy-390xx-kernel-dkms", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-legacy-390xx-kernel-source", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-legacy-390xx-kernel-support", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-legacy-390xx-nonglvnd-vulkan-icd", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-legacy-390xx-opencl-icd", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-legacy-390xx-smi", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-legacy-390xx-vdpau-driver", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-legacy-390xx-vulkan-icd", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-video-nvidia-legacy-390xx", ver:"390.157-1~deb10u1", rls:"DEB10"))) {
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
