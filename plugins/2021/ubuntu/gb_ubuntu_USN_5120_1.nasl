# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.845108");
  script_version("2021-10-28T14:01:13+0000");
  script_cve_id("CVE-2019-19449", "CVE-2020-26541", "CVE-2020-36311", "CVE-2021-22543", "CVE-2021-3612", "CVE-2021-3759", "CVE-2021-38199", "CVE-2021-38207", "CVE-2021-40490");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-29 11:15:42 +0000 (Fri, 29 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-13 18:30:00 +0000 (Tue, 13 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-10-22 01:00:27 +0000 (Fri, 22 Oct 2021)");
  script_name("Ubuntu: Security Advisory for linux-azure-5.8 (USN-5120-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04 LTS");

  script_xref(name:"Advisory-ID", value:"USN-5120-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-October/006248.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure-5.8'
  package(s) announced via the USN-5120-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the f2fs file system in the Linux kernel did not
properly validate metadata in some situations. An attacker could use this
to construct a malicious f2fs image that, when mounted and operated on,
could cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2019-19449)

It was discovered that the Linux kernel did not properly enforce certain
types of entries in the Secure Boot Forbidden Signature Database (aka dbx)
protection mechanism. An attacker could use this to bypass UEFI Secure Boot
restrictions. (CVE-2020-26541)

It was discovered that the KVM hypervisor implementation for AMD processors
in the Linux kernel did not ensure enough processing time was given to
perform cleanups of large SEV VMs. A local attacker could use this to cause
a denial of service (soft lockup). (CVE-2020-36311)

It was discovered that the KVM hypervisor implementation in the Linux
kernel did not properly perform reference counting in some situations,
leading to a use-after-free vulnerability. An attacker who could start and
control a VM could possibly use this to expose sensitive information or
execute arbitrary code. (CVE-2021-22543)

Murray McAllister discovered that the joystick device interface in the
Linux kernel did not properly validate data passed via an ioctl(). A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code on systems with a joystick device
registered. (CVE-2021-3612)

It was discovered that the Linux kernel did not properly account for the
memory usage of certain IPC objects. A local attacker could use this to
cause a denial of service (memory exhaustion). (CVE-2021-3759)

Michael Wakabayashi discovered that the NFSv4 client implementation in the
Linux kernel did not properly order connection setup operations. An
attacker controlling a remote NFS server could use this to cause a denial
of service on the client. (CVE-2021-38199)

It was discovered that the Xilinx LL TEMAC device driver in the Linux
kernel did not properly calculate the number of buffers to be used in
certain situations. A remote attacker could use this to cause a denial of
service (system crash). (CVE-2021-38207)

It was discovered that the ext4 file system in the Linux kernel contained a
race condition when writing xattrs to an inode. A local attacker could use
this to cause a denial of service or possibly gain administrative
privileges. (CVE-2021-40490)");

  script_tag(name:"affected", value:"'linux-azure-5.8' package(s) on Ubuntu 20.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1043-azure", ver:"5.8.0-1043.46~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.8.0.1043.46~20.04.15", rls:"UBUNTU20.04 LTS"))) {
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