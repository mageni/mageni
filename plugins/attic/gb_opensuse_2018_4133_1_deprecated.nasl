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
  script_oid("1.3.6.1.4.1.25623.1.0.852195");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_cve_id("CVE-2018-18281");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2018-12-18 07:42:17 +0100 (Tue, 18 Dec 2018)");
  script_name("openSUSE: Security Advisory for kernel (openSUSE-SU-2018:4133-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");

  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00035.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the openSUSE-SU-2018:4133-1 advisory.

  This NVT has been replaced by OID: 1.3.6.1.4.1.25623.1.0.814563");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The openSUSE Leap 15.0 kernel was updated
  to 4.12.14-lp150.12.28.1 to receive various security and bugfixes.


  The following security bugs were fixed:

  - CVE-2018-18281: The mremap() syscall performs TLB flushes after dropping
  pagetable locks. If a syscall such as ftruncate() removes entries from
  the pagetables of a task that is in the middle of mremap(), a stale TLB
  entry can remain for a short time that permits access to a physical page
  after it has been released back to the page allocator and reused.
  (bnc#1113769).


  The following non-security bugs were fixed:

  - ACPI / LPSS: Add alternative ACPI HIDs for Cherry Trail DMA controllers
  (bsc#1051510).

  - ACPI / platform: Add SMB0001 HID to forbidden_id_list (bsc#1051510).

  - ACPI / watchdog: Prefer iTCO_wdt always when WDAT table uses RTC SRAM
  (bsc#1051510).

  - ACPI/APEI: Handle GSIV and GPIO notification types (bsc#1115567).

  - ACPI/IORT: Fix iort_get_platform_device_domain() uninitialized pointer
  value (bsc#1051510).

  - ACPICA: Tables: Add WSMT support (bsc#1089350).

  - ALSA: ac97: Fix incorrect bit shift at AC97-SPSA control write
  (bsc#1051510).

  - ALSA: ca0106: Disable IZD on SB0570 DAC to fix audio pops (bsc#1051510).

  - ALSA: control: Fix race between adding and removing a user element
  (bsc#1051510).

  - ALSA: hda/ca0132 - Call pci_iounmap() instead of iounmap() (bsc#1051510).

  - ALSA: hda/realtek - Add GPIO data update helper (bsc#1051510).

  - ALSA: hda/realtek - Add auto-mute quirk for HP Spectre x360 laptop
  (bsc#1051510).

  - ALSA: hda/realtek - Allow skipping spec- init_amp detection
  (bsc#1051510).

  - ALSA: hda/realtek - Fix HP Headset Mic can't record (bsc#1051510).

  - ALSA: hda/realtek - Manage GPIO bits commonly (bsc#1051510).

  - ALSA: hda/realtek - Simplify Dell XPS13 GPIO handling (bsc#1051510).

  - ALSA: hda/realtek - Support ALC300 (bsc#1051510).

  - ALSA: hda/realtek - fix headset mic detection for MSI MS-B171
  (bsc#1051510).

  - ALSA: hda/realtek - fix the pop noise on headphone for lenovo laptops
  (bsc#1051510).

  - ALSA: hda: Add ASRock N68C-S UCC the power_save blacklist (bsc#1051510).

  - ALSA: oss: Use kvzalloc() for local buffer allocations (bsc#1051510).

  - ALSA: sparc: Fix invalid snd_free_pages() at error path (bsc#1051510).

  - ALSA: usb-audio: Add vendor and product name for Dell WD19 Dock
  (bsc#1051510).

  - ALSA: wss: Fix invalid snd_free_pages() at error path (bsc#1051510).

  - ARM: dts: at91: add new compatibility string for macb on sama5d3
  (bsc#1051510).

  - ASoC: Intel: cht_bsw_max98090: add support for Baytrail (bsc#1051510).

  - ASoC: dwc: Added a  ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"the on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in OID: 1.3.6.1.4.1.25623.1.0.814563
