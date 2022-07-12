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
  script_oid("1.3.6.1.4.1.25623.1.0.854221");
  script_version("2021-10-28T14:01:13+0000");
  script_cve_id("CVE-2020-3702", "CVE-2021-3669", "CVE-2021-3744", "CVE-2021-3752", "CVE-2021-3764", "CVE-2021-40490");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-29 11:15:42 +0000 (Fri, 29 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-10 17:17:00 +0000 (Fri, 10 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-10-16 01:07:28 +0000 (Sat, 16 Oct 2021)");
  script_name("openSUSE: Security Advisory for the (openSUSE-SU-2021:3447-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:3447-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IAN74FTXJ7PFHCBV6YMLTPNW7VFYCPFV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the'
  package(s) announced via the openSUSE-SU-2021:3447-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated.


     The following security bugs were fixed:

  - CVE-2020-3702: Fixed a bug which could be triggered with specifically
       timed and handcrafted traffic and cause internal errors in a WLAN device
       that lead to improper layer 2 Wi-Fi encryption with a consequent
       possibility of information disclosure. (bnc#1191193)

  - CVE-2021-3752: Fixed a use after free vulnerability in the Linux
       kernel&#x27 s bluetooth module. (bsc#1190023)

  - CVE-2021-40490: Fixed a race condition discovered in the ext4 subsystem
       that could lead to local privilege  escalation. (bnc#1190159)

  - CVE-2021-3744: Fixed a bug which could allows attackers to cause a
       denial of service. (bsc#1189884)

  - CVE-2021-3764: Fixed a bug which could allows attackers to cause a
       denial of service. (bsc#1190534)

  - CVE-2021-3669: Fixed a bug that doesn&#x27 t allow /proc/sysvipc/shm to scale
       with large shared memory segment counts which could lead to resource
       exhaustion and DoS. (bsc#1188986)

     The following non-security bugs were fixed:

  - ALSA: firewire-motu: fix truncated bytes in message tracepoints
       (git-fixes).

  - apparmor: remove duplicate macro list_entry_is_head() (git-fixes).

  - ASoC: fsl_micfil: register platform component before registering cpu dai
       (git-fixes).

  - ASoC: mediatek: common: handle NULL case in suspend/resume function
       (git-fixes).

  - ASoC: rockchip: i2s: Fix regmap_ops hang (git-fixes).

  - ASoC: rockchip: i2s: Fixup config for DAIFMT_DSP_A/B (git-fixes).

  - ASoC: SOF: Fix DSP oops stack dump output contents (git-fixes).

  - ath9k: fix OOB read ar9300_eeprom_restore_internal (git-fixes).

  - ath9k: fix sleeping in atomic context (git-fixes).

  - blk-mq: do not deactivate hctx if managed irq isn&#x27 t used (bsc#1185762).

  - blk-mq: kABI fixes for blk_mq_queue_map (bsc#1185762).

  - blk-mq: mark if one queue map uses managed irq (bsc#1185762).

  - Bluetooth: skip invalid hci_sync_conn_complete_evt (git-fixes).

  - bnx2x: fix an error code in bnx2x_nic_load() (git-fixes).

  - bnxt_en: Add missing DMA memory barriers (git-fixes).

  - bnxt_en: Disable aRFS if running on 212 firmware (git-fixes).

  - bnxt_en: Do not enable legacy TX push on older firmware (git-fixes).

  - bnxt_en: Store the running firmware version code (git-fixes).

  - bnxt: count Tx drops (git-fixes).

  - bnxt: disable napi before canceling DIM (git-fixes).

  - bnxt: do not lock the tx queue from napi poll (git-fixes).
    ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"kmod-compat-25", rpm:"kmod-compat-25~6.10.1", rls:"openSUSELeap15.3"))) {
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
