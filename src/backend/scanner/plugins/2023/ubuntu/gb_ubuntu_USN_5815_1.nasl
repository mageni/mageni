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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5815.1");
  script_cve_id("CVE-2022-20421", "CVE-2022-2663", "CVE-2022-3061", "CVE-2022-3303", "CVE-2022-3586", "CVE-2022-3646", "CVE-2022-39842", "CVE-2022-40307", "CVE-2022-4095", "CVE-2022-43750");
  script_tag(name:"creation_date", value:"2023-01-20 04:10:35 +0000 (Fri, 20 Jan 2023)");
  script_version("2023-02-08T10:09:54+0000");
  script_tag(name:"last_modification", value:"2023-02-08 10:09:54 +0000 (Wed, 08 Feb 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-13 02:50:00 +0000 (Thu, 13 Oct 2022)");

  script_name("Ubuntu: Security Advisory (USN-5815-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5815-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5815-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-bluefield' package(s) announced via the USN-5815-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition existed in the Android Binder IPC
subsystem in the Linux kernel, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2022-20421)

David Leadbeater discovered that the netfilter IRC protocol tracking
implementation in the Linux Kernel incorrectly handled certain message
payloads in some situations. A remote attacker could possibly use this to
cause a denial of service or bypass firewall filtering. (CVE-2022-2663)

It was discovered that the Intel 740 frame buffer driver in the Linux
kernel contained a divide by zero vulnerability. A local attacker could use
this to cause a denial of service (system crash). (CVE-2022-3061)

It was discovered that the sound subsystem in the Linux kernel contained a
race condition in some situations. A local attacker could use this to cause
a denial of service (system crash). (CVE-2022-3303)

Gwnaun Jung discovered that the SFB packet scheduling implementation in the
Linux kernel contained a use-after-free vulnerability. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2022-3586)

It was discovered that the NILFS2 file system implementation in the Linux
kernel did not properly deallocate memory in certain error conditions. An
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2022-3646)

Hyunwoo Kim discovered that an integer overflow vulnerability existed in
the PXA3xx graphics driver in the Linux kernel. A local attacker could
possibly use this to cause a denial of service (system crash).
(CVE-2022-39842)

It was discovered that a race condition existed in the EFI capsule loader
driver in the Linux kernel, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2022-40307)

Zheng Wang and Zhuorao Yang discovered that the RealTek RTL8712U wireless
driver in the Linux kernel contained a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2022-4095)

It was discovered that the USB monitoring (usbmon) component in the Linux
kernel did not properly set permissions on memory mapped in to user space
processes. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-43750)");

  script_tag(name:"affected", value:"'linux-bluefield' package(s) on Ubuntu 20.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1054-bluefield", ver:"5.4.0-1054.60", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-bluefield", ver:"5.4.0.1054.50", rls:"UBUNTU20.04 LTS"))) {
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
