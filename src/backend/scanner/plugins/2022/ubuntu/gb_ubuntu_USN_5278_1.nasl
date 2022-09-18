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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5278.1");
  script_cve_id("CVE-2020-27820", "CVE-2021-22600", "CVE-2021-28713", "CVE-2021-28714", "CVE-2021-28715", "CVE-2021-39685", "CVE-2021-4001", "CVE-2021-4083", "CVE-2021-4135", "CVE-2021-4155", "CVE-2021-4197", "CVE-2021-43975", "CVE-2021-44733", "CVE-2021-45095", "CVE-2021-45480", "CVE-2022-0264", "CVE-2022-0330", "CVE-2022-0382", "CVE-2022-22942", "CVE-2022-23222", "CVE-2022-24122");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-05 03:15:00 +0000 (Sat, 05 Feb 2022)");

  script_name("Ubuntu: Security Advisory (USN-5278-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5278-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5278-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-5.14' package(s) announced via the USN-5278-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the rlimit tracking for user namespaces in the Linux
kernel did not properly perform reference counting, leading to a use-after-
free vulnerability. A local attacker could use this to cause a denial of
service or possibly execute arbitrary code. (CVE-2022-24122)

It was discovered that the BPF verifier in the Linux kernel did not
properly restrict pointer types in certain situations. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2022-23222)

Jeremy Cline discovered a use-after-free in the nouveau graphics driver of
the Linux kernel during device removal. A privileged or physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2020-27820)

It was discovered that the Packet network protocol implementation in the
Linux kernel contained a double-free vulnerability. A local attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2021-22600)

Jurgen Gross discovered that the Xen subsystem within the Linux kernel did
not adequately limit the number of events driver domains (unprivileged PV
backends) could send to other guest VMs. An attacker in a driver domain
could use this to cause a denial of service in other guest VMs.
(CVE-2021-28713)

Jurgen Gross discovered that the Xen network backend driver in the Linux
kernel did not adequately limit the amount of queued packets when a guest
did not process them. An attacker in a guest VM can use this to cause a
denial of service (excessive kernel memory consumption) in the network
backend domain. (CVE-2021-28714, CVE-2021-28715)

Szymon Heidrich discovered that the USB Gadget subsystem in the Linux
kernel did not properly restrict the size of control requests for certain
gadget types, leading to possible out of bounds reads or writes. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2021-39685)

It was discovered that the eBPF implementation in the Linux kernel
contained a race condition around read-only maps. A privileged attacker
could use this to modify read-only maps. (CVE-2021-4001)

Jann Horn discovered a race condition in the Unix domain socket
implementation in the Linux kernel that could result in a read-after-free.
A local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2021-4083)

It was discovered that the simulated networking device driver for the Linux
kernel did not properly initialize memory in certain situations. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2021-4135)

Kirill Tkhai discovered that the XFS file system implementation in the
Linux kernel did not calculate size correctly when pre-allocating space in
some situations. A local attacker could use this to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-oem-5.14' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.14.0-1022-oem", ver:"5.14.0-1022.24", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04d", ver:"5.14.0.1022.19", rls:"UBUNTU20.04 LTS"))) {
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
