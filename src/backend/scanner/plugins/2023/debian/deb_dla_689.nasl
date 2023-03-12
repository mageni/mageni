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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.689");
  script_cve_id("CVE-2016-7909", "CVE-2016-8909", "CVE-2016-8910", "CVE-2016-9101", "CVE-2016-9102", "CVE-2016-9103", "CVE-2016-9104", "CVE-2016-9105", "CVE-2016-9106");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-10 18:54:00 +0000 (Tue, 10 Nov 2020)");

  script_name("Debian: Security Advisory (DLA-689)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-689");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-689");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu-kvm' package(s) announced via the DLA-689 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in qemu-kvm, a full virtualization solution on x86 hardware based on Quick Emulator(Qemu). The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2016-7909

Quick Emulator(Qemu) built with the AMD PC-Net II emulator support is vulnerable to an infinite loop issue. It could occur while receiving packets via pcnet_receive().

A privileged user/process inside guest could use this issue to crash the Qemu process on the host leading to DoS.

CVE-2016-8909

Quick Emulator(Qemu) built with the Intel HDA controller emulation support is vulnerable to an infinite loop issue. It could occur while processing the DMA buffer stream while doing data transfer in intel_hda_xfer.

A privileged user inside guest could use this flaw to consume excessive CPU cycles on the host, resulting in DoS.

CVE-2016-8910

Quick Emulator(Qemu) built with the RTL8139 ethernet controller emulation support is vulnerable to an infinite loop issue. It could occur while transmitting packets in C+ mode of operation.

A privileged user inside guest could use this flaw to consume excessive CPU cycles on the host, resulting in DoS situation.

Further issues fixed where the CVE requests are pending:

Quick Emulator(Qemu) built with the i8255x (PRO100) NIC emulation support is vulnerable to a memory leakage issue. It could occur while unplugging the device, and doing so repeatedly would result in leaking host memory affecting, other services on the host. A privileged user inside guest could use this flaw to cause a DoS on the host and/or potentially crash the Qemu process on the host.

Quick Emulator(Qemu) built with the VirtFS, host directory sharing via Plan 9 File System(9pfs) support, is vulnerable to a several memory leakage issues. A privileged user inside guest could use this flaw to leak the host memory bytes resulting in DoS for other services.

Quick Emulator(Qemu) built with the VirtFS, host directory sharing via Plan 9 File System(9pfs) support, is vulnerable to an integer overflow issue. It could occur by accessing xattributes values. A privileged user inside guest could use this flaw to crash the Qemu process instance resulting in DoS.

Quick Emulator(Qemu) built with the VirtFS, host directory sharing via Plan 9 File System(9pfs) support, is vulnerable to memory leakage issue. It could occur while creating extended attribute via Txattrcreate message. A privileged user inside guest could use this flaw to leak host memory, thus affecting other services on the host and/or potentially crash the Qemu process on the host.

For Debian 7 Wheezy, these problems have been fixed in version 1.1.2+dfsg-6+deb7u18.

We recommend that you upgrade your qemu-kvm packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"kvm", ver:"1:1.1.2+dfsg-6+deb7u18", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm-dbg", ver:"1.1.2+dfsg-6+deb7u18", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"1.1.2+dfsg-6+deb7u18", rls:"DEB7"))) {
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
