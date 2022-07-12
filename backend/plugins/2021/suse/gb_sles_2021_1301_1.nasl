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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1301.1");
  script_cve_id("CVE-2020-25670", "CVE-2020-25671", "CVE-2020-25672", "CVE-2020-25673", "CVE-2020-36310", "CVE-2020-36311", "CVE-2020-36312", "CVE-2021-28950", "CVE-2021-29154", "CVE-2021-30002", "CVE-2021-3483");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:39 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-06-18T08:30:00+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-23 02:15:00 +0000 (Wed, 23 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1301-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1301-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211301-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:1301-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-25670, CVE-2020-25671, CVE-2020-25672, CVE-2020-25673: Fixed
 multiple bugs in NFC subsytem (bsc#1178181).

CVE-2020-36311: Fixed a denial of service (soft lockup) by triggering
 destruction of a large SEV VM (bsc#1184511).

CVE-2021-29154: Fixed incorrect computation of branch displacements,
 allowing arbitrary code execution (bsc#1184391).

CVE-2021-30002: Fixed a memory leak for large arguments in
 video_usercopy (bsc#1184120).

CVE-2021-3483: Fixed a use-after-free in nosy.c (bsc#1184393).

CVE-2020-36310: Fixed infinite loop for certain nested page faults
 (bsc#1184512).

CVE-2020-36312: Fixed a memory leak upon a kmalloc failure (bsc#1184509
 ).

CVE-2021-28950: Fixed an issue in fs/fuse/fuse_i.h due to a retry loop
 continually was finding the same bad inode (bsc#1184194).

The following non-security bugs were fixed:

ALSA: aloop: Fix initialization of controls (git-fixes).

ALSA: hda/realtek: Fix speaker amp setup on Acer Aspire E1 (git-fixes).

appletalk: Fix skb allocation size in loopback case (git-fixes).

ASoC: cygnus: fix for_each_child.cocci warnings (git-fixes).

ASoC: fsl_esai: Fix TDM slot setup for I2S mode (git-fixes).

ASoC: intel: atom: Remove 44100 sample-rate from the media and
 deep-buffer DAI descriptions (git-fixes).

ASoC: intel: atom: Stop advertising non working S24LE support
 (git-fixes).

ASoC: max98373: Added 30ms turn on/off time delay (git-fixes).

ASoC: sunxi: sun4i-codec: fill ASoC card owner (git-fixes).

ASoC: wm8960: Fix wrong bclk and lrclk with pll enabled for some chips
 (git-fixes).

ath10k: hold RCU lock when calling ieee80211_find_sta_by_ifaddr()
 (git-fixes).

atl1c: fix error return code in atl1c_probe() (git-fixes).

atl1e: fix error return code in atl1e_probe() (git-fixes).

batman-adv: initialize 'struct batadv_tvlv_tt_vlan_data'->reserved field
 (git-fixes).

bpf: Remove MTU check in __bpf_skb_max_len (bsc#1155518).

brcmfmac: clear EAP/association status bits on linkdown events
 (git-fixes).

bus: ti-sysc: Fix warning on unbind if reset is not deasserted
 (git-fixes).

cifs: change noisy error message to FYI (bsc#1181507).

cifs_debug: use %pd instead of messing with ->d_name (bsc#1181507).

cifs: do not send close in compound create+close requests (bsc#1181507).

cifs: New optype for session operations (bsc#1181507).

cifs: print MIDs in decimal notation (bsc#1181507).

cifs: return proper error code in statfs(2) (bsc#1181507).

cifs: Tracepoints and logs for tracing credit changes (bsc#1181507).

clk: fix invalid usage of list cursor in register (git-fixes).

clk: fix invalid usage of list cursor in unregister (git-fixes).

clk: socfpga: fix iomem pointer cast on 64-bit (git-fixes).

drivers: video: fbcon: fix NULL dereference in fbcon_cursor()
 (git-fixes).

drm/amdgpu:... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP2");

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

if(release == "SLES15.0SP2") {
  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~18.44.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~18.44.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~18.44.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~18.44.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~18.44.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~18.44.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~18.44.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~18.44.1", rls:"SLES15.0SP2"))){
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
