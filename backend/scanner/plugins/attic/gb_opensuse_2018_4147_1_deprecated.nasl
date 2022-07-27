# Copyright (C) 2018 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852186");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_cve_id("CVE-2018-10839", "CVE-2018-15746", "CVE-2018-17958",
                "CVE-2018-17962", "CVE-2018-17963", "CVE-2018-18849");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2018-12-18 07:41:02 +0100 (Tue, 18 Dec 2018)");
  script_name("openSUSE: Security Advisory for qemu (openSUSE-SU-2018:4147-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");

  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00043.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the openSUSE-SU-2018:4147-1 advisory.

  This NVT has been replaced by OID: 1.3.6.1.4.1.25623.1.0.814570");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

  Security issues fixed:

  - CVE-2018-10839: Fixed NE2000 NIC emulation support that is vulnerable to
  an integer overflow, which could lead to buffer overflow issue. It could
  occur when receiving packets over the network. A user inside guest could
  use this flaw to crash the Qemu process resulting in DoS (bsc#1110910).

  - CVE-2018-15746: Fixed qemu-seccomp.c that might allow local OS guest
  users to cause a denial of service (guest crash) by leveraging
  mishandling of the seccomp policy for threads other than the main thread
  (bsc#1106222).

  - CVE-2018-17958: Fixed a Buffer Overflow in rtl8139_do_receive in
  hw/net/rtl8139.c because an incorrect integer data type is used
  (bsc#1111006).

  - CVE-2018-17962: Fixed a Buffer Overflow in pcnet_receive in
  hw/net/pcnet.c because an incorrect integer data type is used
  (bsc#1111010).

  - CVE-2018-17963: Fixed qemu_deliver_packet_iov in net/net.c that accepts
  packet sizes greater than INT_MAX, which allows attackers to cause a
  denial of service or possibly have unspecified other impact.
  (bsc#1111013)

  - CVE-2018-18849: Fixed an out of bounds memory access issue that was
  found in the LSI53C895A SCSI Host Bus Adapter emulation while writing a
  message in lsi_do_msgin. It could occur during migration if the
  'msg_len' field has an invalid value. A user/process could use this flaw
  to crash the Qemu process resulting in DoS (bsc#1114422).

  Non-security issues fixed:

  - Improving disk performance for qemu on xen (bsc#1100408)

  This update was imported from the SUSE:SLE-12-SP3:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1563=1");

  script_tag(name:"affected", value:"qemu on openSUSE Leap 42.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in OID: 1.3.6.1.4.1.25623.1.0.814570
