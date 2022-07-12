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
  script_oid("1.3.6.1.4.1.25623.1.0.852188");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2018-12-18 07:41:31 +0100 (Tue, 18 Dec 2018)");
  script_name("openSUSE: Security Advisory for kernel (openSUSE-SU-2018:4132-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");

  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00034.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the openSUSE-SU-2018:4132-1 advisory.

  This NVT has been replaced by OID: 1.3.6.1.4.1.25623.1.0.814561");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The openSUSE Leap 42.3 kernel was updated
  to 4.4.165-81.1 to receive various bugfixes.


  The following non-security bugs were fixed:

  - 9p locks: fix glock.client_id leak in do_lock (bnc#1012382).

  - 9p: clear dangling pointers in p9stat_free (bnc#1012382).

  - ACPI / LPSS: Add alternative ACPI HIDs for Cherry Trail DMA controllers
  (bnc#1012382).

  - ACPI / platform: Add SMB0001 HID to forbidden_id_list (bnc#1012382).

  - ALSA: ca0106: Disable IZD on SB0570 DAC to fix audio pops (bnc#1012382).

  - ALSA: hda - Add mic quirk for the Lenovo G50-30 (17aa:3905)
  (bnc#1012382).

  - ALSA: hda: Check the non-cached stream buffers more explicitly
  (bnc#1012382).

  - ALSA: timer: Fix zero-division by continue of uninitialized instance
  (bnc#1012382).

  - ARM64: PCI: ACPI support for legacy IRQs parsing and consolidation with
  DT code (bsc#985031).

  - ARM: 8799/1: mm: fix pci_ioremap_io() offset check (bnc#1012382).

  - ARM: dts: apq8064: add ahci ports-implemented mask (bnc#1012382).

  - ARM: dts: imx53-qsb: disable 1.2GHz OPP (bnc#1012382).

  - ASoC: ak4613: Enable cache usage to fix crashes on resume (bnc#1012382).

  - ASoC: spear: fix error return code in spdif_in_probe() (bnc#1012382).

  - ASoC: wm8940: Enable cache usage to fix crashes on resume (bnc#1012382).

  - Bluetooth: SMP: fix crash in unpairing (bnc#1012382).

  - Bluetooth: btbcm: Add entry for BCM4335C0 UART bluetooth (bnc#1012382).

  - Btrfs: fix data corruption due to cloning of eof block (bnc#1012382).

  - Btrfs: fix null pointer dereference on compressed write path error
  (bnc#1012382).

  - Btrfs: fix wrong dentries after fsync of file that got its parent
  replaced (bnc#1012382).

  - CIFS: handle guest access errors to Windows shares (bnc#1012382).

  - Cramfs: fix abad comparison when wrap-arounds occur (bnc#1012382).

  - Fix kABI for 'Ensure we commit after writeback is complete'
  (bsc#1111809).

  - HID: hiddev: fix potential Spectre v1 (bnc#1012382).

  - HID: uhid: forbid UHID_CREATE under KERNEL_DS or elevated privileges
  (bnc#1012382).

  - IB/ucm: Fix Spectre v1 vulnerability (bnc#1012382).

  - Input: elan_i2c - add ACPI ID for Lenovo IdeaPad 330-15IGM (bnc#1012382).

  - KEYS: put keyring if install_session_keyring_to_cred() fails
  (bnc#1012382).

  - KVM: nVMX: Always reflect #NM VM-exits to L1 (bsc#1106240).

  - MD: fix invalid stored role for a disk (bnc#1012382).

  - MD: fix invalid stored role for a disk - try2 (bnc#1012382).

  - MIPS: DEC: Fix an int-handler.S CPU_DADDI_WORKAROUNDS regression
  (bnc#1012382).

  - MIPS: Fix FCSR Cause bit handling for correct SIGFPE issue (bnc#1012382).

  - MIPS: Handle ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"the on openSUSE Leap 42.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in OID: 1.3.6.1.4.1.25623.1.0.814561
