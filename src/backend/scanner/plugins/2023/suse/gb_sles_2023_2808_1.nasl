# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2808.1");
  script_cve_id("CVE-2023-1077", "CVE-2023-1079", "CVE-2023-1249", "CVE-2023-1637", "CVE-2023-2002", "CVE-2023-3090", "CVE-2023-3111", "CVE-2023-3141", "CVE-2023-3159", "CVE-2023-3161", "CVE-2023-3268", "CVE-2023-3358", "CVE-2023-35824");
  script_tag(name:"creation_date", value:"2023-07-12 04:21:59 +0000 (Wed, 12 Jul 2023)");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-09 22:51:00 +0000 (Fri, 09 Jun 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2808-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2808-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232808-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:2808-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:

CVE-2023-1077: Fixed a type confusion in pick_next_rt_entity(), that could cause memory corruption (bsc#1208600).
CVE-2023-1079: Fixed a use-after-free problem that could have been triggered in asus_kbd_backlight_set when plugging/disconnecting a malicious USB device (bsc#1208604).
CVE-2023-1249: Fixed a use-after-free flaw in the core dump subsystem that allowed a local user to crash the system (bsc#1209039).
CVE-2023-1637: Fixed vulnerability that could lead to unauthorized access to CPU memory after resuming CPU from suspend-to-RAM (bsc#1209779).
CVE-2023-2002: Fixed a flaw that allowed an attacker to unauthorized execution of management commands, compromising the confidentiality, integrity, and availability of Bluetooth communication (bsc#1210533).
CVE-2023-3090: Fixed a heap out-of-bounds write in the ipvlan network driver (bsc#1212842).
CVE-2023-3111: Fixed a use-after-free vulnerability in prepare_to_relocate in fs/btrfs/relocation.c (bsc#1212051).
CVE-2023-3141: Fixed a use-after-free flaw in r592_remove in drivers/memstick/host/r592.c, that allowed local attackers to crash the system at device disconnect (bsc#1212129).
CVE-2023-3159: Fixed use-after-free issue in driver/firewire in outbound_phy_packet_callback (bsc#1212128).
CVE-2023-3161: Fixed shift-out-of-bounds in fbcon_set_font() (bsc#1212154).
CVE-2023-3268: Fixed an out of bounds (OOB) memory access flaw in relay_file_read_start_pos in kernel/relay.c (bsc#1212502).
CVE-2023-3358: Fixed a NULL pointer dereference flaw in the Integrated Sensor Hub (ISH) driver (bsc#1212606).
CVE-2023-35824: Fixed a use-after-free in dm1105_remove in drivers/media/pci/dm1105/dm1105.c (bsc#1212501).

The following non-security bugs were fixed:

Also include kernel-docs build requirements for ALP Avoid unsuported tar parameter on SLE12 CDC-NCM: avoid overflow in sanity checking (git-fixes).
CIFS: Spelling s/EACCESS/EACCES/ (bsc#1190317).
Decrease the number of SMB3 smbdirect client SGEs (bsc#1190317).
Fix formatting of client smbdirect RDMA logging (bsc#1190317).
Fix missing top level chapter numbers on SLE12 SP5 (bsc#1212158).
Generalize kernel-doc build requirements.
Handle variable number of SGEs in client smbdirect send (bsc#1190317).
Move obsolete KMP list into a separate file. The list of obsoleted KMPs varies per release, move it out of the spec file.
Move setting %%build_html to config.sh Move setting %%split_optional to config.sh Move setting %%supported_modules_check to config.sh Move the kernel-binary conflicts out of the spec file. Thie list of conflicting packages varies per release. To reduce merge conflicts move the list out of the spec file.
PCI/MSI: Clear PCI_MSIX_FLAGS_MASKALL on error (git-fixes).
PCI/MSI: Destroy sysfs before freeing entries (git-fixes).
PCI/MSI: Fix ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.139.1", rls:"SLES12.0SP5"))) {
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
