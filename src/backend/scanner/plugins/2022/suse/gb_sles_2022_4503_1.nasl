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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4503.1");
  script_cve_id("CVE-2022-2602", "CVE-2022-28693", "CVE-2022-3567", "CVE-2022-3628", "CVE-2022-3635", "CVE-2022-3707", "CVE-2022-3903", "CVE-2022-4095", "CVE-2022-4129", "CVE-2022-4139", "CVE-2022-41850", "CVE-2022-41858", "CVE-2022-42895", "CVE-2022-42896", "CVE-2022-4378", "CVE-2022-43945", "CVE-2022-45934");
  script_tag(name:"creation_date", value:"2022-12-19 04:19:33 +0000 (Mon, 19 Dec 2022)");
  script_version("2022-12-19T04:19:33+0000");
  script_tag(name:"last_modification", value:"2022-12-19 04:19:33 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-28 01:27:00 +0000 (Mon, 28 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4503-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4503-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224503-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:4503-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2022-4378: Fixed stack overflow in __do_proc_dointvec (bsc#1206207).

CVE-2022-3635: Fixed a use-after-free in the tst_timer() of the file
 drivers/atm/idt77252.c of the component IPsec (bsc#1204631).

CVE-2022-41850: Fixed a race condition in roccat_report_event() in
 drivers/hid/hid-roccat.c (bsc#1203960).

CVE-2022-45934: Fixed a integer wraparound via L2CAP_CONF_REQ packets in
 l2cap_config_req in net/bluetooth/l2cap_core.c (bsc#1205796).

CVE-2022-3628: Fixed potential buffer overflow in
 brcmf_fweh_event_worker() in wifi/brcmfmac (bsc#1204868).

CVE-2022-3567: Fixed a to race condition in
 inet6_stream_ops()/inet6_dgram_ops() of the component IPv6 Handler
 (bsc#1204414).

CVE-2022-41858: Fixed a denial of service in sl_tx_timeout() in
 drivers/net/slip (bsc#1205671).

CVE-2022-43945: Fixed a buffer overflow in the NFSD implementation
 (bsc#1205128).

CVE-2022-4095: Fixed a use-after-free in rtl8712 driver (bsc#1205514).

CVE-2022-3903: Fixed a denial of service with the Infrared Transceiver
 USB driver (bsc#1205220).

CVE-2022-2602: Fixed a local privilege escalation vulnerability
 involving Unix socket Garbage Collection and io_uring (bsc#1204228).

CVE-2022-4139: Fixed an issue with the i915 driver that allowed the GPU
 to access any physical memory (bsc#1205700).

CVE-2022-4129: Fixed a denial of service with the Layer 2 Tunneling
 Protocol (L2TP). A missing lock when clearing sk_user_data can lead to a
 race condition and NULL pointer dereference. (bsc#1205711)

CVE-2022-42895: Fixed an information leak in the
 net/bluetooth/l2cap_core.c's l2cap_parse_conf_req() which can be used to
 leak kernel pointers remotely (bsc#1205705).

CVE-2022-42896: Fixed a use-after-free vulnerability in the
 net/bluetooth/l2cap_core.c's l2cap_connect() and l2cap_le_connect_req()
 which may have allowed code execution and leaking kernel memory
 (respectively) remotely via Bluetooth (bsc#1205709).

CVE-2022-3707: Fixed a double free in the Intel GVT-g graphics driver
 (bsc#1204780).

The following non-security bugs were fixed:

ALSA: hda/ca0132: add quirk for EVGA Z390 DARK (git-fixes).

ALSA: hda: fix potential memleak in 'add_widget_node' (git-fixes).

ALSA: usb-audio: Add DSD support for Accuphase DAC-60 (git-fixes).

ALSA: usb-audio: Add quirk entry for M-Audio Micro (git-fixes).

ALSA: usb-audio: Drop snd_BUG_ON() from snd_usbmidi_output_open()
 (git-fixes).

ASoC: codecs: jz4725b: Fix spelling mistake 'Sourc' -> 'Source',
 'Routee' -> 'Route' (git-fixes).

ASoC: codecs: jz4725b: add missed Line In power control bit (git-fixes).

ASoC: codecs: jz4725b: fix capture selector naming (git-fixes).

ASoC: codecs: jz4725b: fix reported volume for Master ctl (git-fixes).

ASoC: codecs: jz4725b: use right control for Capture Volume ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~150300.38.88.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~150300.38.88.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~150300.38.88.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~150300.38.88.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~150300.38.88.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~150300.38.88.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~150300.38.88.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~150300.38.88.1", rls:"SLES15.0SP3"))) {
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
