# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3508");
  script_cve_id("CVE-2023-1380", "CVE-2023-2002", "CVE-2023-2007", "CVE-2023-20593", "CVE-2023-2269", "CVE-2023-3090", "CVE-2023-31084", "CVE-2023-3111", "CVE-2023-3141", "CVE-2023-32233", "CVE-2023-3268", "CVE-2023-3338", "CVE-2023-34256", "CVE-2023-35788", "CVE-2023-35823", "CVE-2023-35824", "CVE-2023-35828");
  script_tag(name:"creation_date", value:"2023-07-31 04:22:04 +0000 (Mon, 31 Jul 2023)");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-23 21:19:00 +0000 (Fri, 23 Jun 2023)");

  script_name("Debian: Security Advisory (DLA-3508)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3508");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3508");
  script_xref(name:"URL", value:"https://lock.cmpxchg8b.com/zenbleed.html");
  script_xref(name:"URL", value:"https://github.com/google/security-research/security/advisories/GHSA-v6wh-rxpg-cmm8");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-3508 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-34256 CVE-2023-35788 CVE-2023-35823 CVE-2023-35824 CVE-2023-35828

Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2023-1380

Jisoo Jang reported a heap out-of-bounds read in the brcmfmac Wi-Fi driver. On systems using this driver, a local user could exploit this to read sensitive information or to cause a denial of service (crash).

CVE-2023-2002

Ruiahn Li reported an incorrect permissions check in the Bluetooth subsystem. A local user could exploit this to reconfigure local Bluetooth interfaces, resulting in information leaks, spoofing, or denial of service (loss of connection).

CVE-2023-2007

Lucas Leong (@_wmliang_) and Reno Robert of Trend Micro Zero Day Initiative discovered a time-of-check-to-time-of-use flaw in the dpt_i2o SCSI controller driver. A local user with access to a SCSI device using this driver could exploit this for privilege escalation.

This flaw has been mitigated by removing support for the I2OUSRCMD operation.

CVE-2023-2269

Zheng Zhang reported that improper handling of locking in the device mapper implementation may result in denial of service.

CVE-2023-3090

It was discovered that missing initialization in ipvlan networking may lead to an out-of-bounds write vulnerability, resulting in denial of service or potentially the execution of arbitrary code.

CVE-2023-3111

The TOTE Robot tool found a flaw in the Btrfs filesystem driver that can lead to a use-after-free. It's unclear whether an unprivileged user can exploit this.

CVE-2023-3141

A flaw was discovered in the r592 memstick driver that could lead to a use-after-free after the driver is removed or unbound from a device. The security impact of this is unclear.

CVE-2023-3268

It was discovered that an out-of-bounds memory access in relayfs could result in denial of service or an information leak.

CVE-2023-3338

Ornaghi Davide discovered a flaw in the DECnet protocol implementation which could lead to a null pointer dereference or use-after-free. A local user can exploit this to cause a denial of service (crash or memory corruption) and probably for privilege escalation.

This flaw has been mitigated by removing the DECnet protocol implementation.

CVE-2023-20593

Tavis Ormandy discovered that under specific microarchitectural circumstances, a vector register in AMD Zen 2 CPUs may not be written to 0 correctly. This flaw allows an attacker to leak sensitive information across concurrent processes, hyper threads and virtualized guests.

For details please refer to [link moved to references] and [link moved to references]

This issue can also be mitigated by a microcode update through the amd64-microcode package or a system firmware (BIOS/UEFI) update. However, the initial microcode release by AMD only provides updates for second generation EPYC CPUs. Various Ryzen CPUs are ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbpf-dev", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbpf4.19", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-arm", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-x86", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-4.19", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.19", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-25-686", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-25-686-pae", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-25-all", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-25-all-amd64", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-25-all-arm64", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-25-all-armhf", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-25-all-i386", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-25-amd64", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-25-arm64", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-25-armmp", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-25-armmp-lpae", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-25-cloud-amd64", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-25-common", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-25-common-rt", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-25-rt-686-pae", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-25-rt-amd64", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-25-rt-arm64", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-25-rt-armmp", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-686-dbg", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-686-pae-dbg", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-686-pae-unsigned", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-686-unsigned", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-amd64-dbg", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-amd64-unsigned", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-arm64-dbg", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-arm64-unsigned", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-armmp", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-armmp-dbg", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-armmp-lpae", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-armmp-lpae-dbg", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-cloud-amd64-dbg", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-cloud-amd64-unsigned", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-rt-686-pae-dbg", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-rt-686-pae-unsigned", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-rt-amd64-dbg", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-rt-amd64-unsigned", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-rt-arm64-dbg", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-rt-arm64-unsigned", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-rt-armmp", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-25-rt-armmp-dbg", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-signed-template", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-signed-template", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-i386-signed-template", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.19", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.19", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.19", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-25", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"2.0+4.19.289-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-25-armmp-di", ver:"4.19.289-1", rls:"DEB10"))) {
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
