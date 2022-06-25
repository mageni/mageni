###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_2497_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for xen openSUSE-SU-2016:2497-1 (xen)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851408");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-12 05:48:02 +0200 (Wed, 12 Oct 2016)");
  script_cve_id("CVE-2014-3615", "CVE-2014-3672", "CVE-2016-3158", "CVE-2016-3159",
                "CVE-2016-3710", "CVE-2016-3712", "CVE-2016-3960", "CVE-2016-4001",
                "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037", "CVE-2016-4439",
                "CVE-2016-4441", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-4480",
                "CVE-2016-4952", "CVE-2016-4962", "CVE-2016-4963", "CVE-2016-5105",
                "CVE-2016-5106", "CVE-2016-5107", "CVE-2016-5126", "CVE-2016-5238",
                "CVE-2016-5337", "CVE-2016-5338", "CVE-2016-5403", "CVE-2016-6258",
                "CVE-2016-6351", "CVE-2016-6833", "CVE-2016-6834", "CVE-2016-6835",
                "CVE-2016-6836", "CVE-2016-6888", "CVE-2016-7092", "CVE-2016-7093",
                "CVE-2016-7094", "CVE-2016-7154");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for xen openSUSE-SU-2016:2497-1 (xen)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for xen fixes the following issues:

  These security issues were fixed:

  - CVE-2016-7092: The get_page_from_l3e function in arch/x86/mm.c in Xen
  allowed local 32-bit PV guest OS administrators to gain host OS
  privileges via vectors related to L3 recursive pagetables (bsc#995785)

  - CVE-2016-7093: Xen allowed local HVM guest OS administrators to
  overwrite hypervisor memory and consequently gain host OS privileges by
  leveraging mishandling of instruction pointer truncation during
  emulation (bsc#995789)

  - CVE-2016-7094: Buffer overflow in Xen allowed local x86 HVM guest OS
  administrators on guests running with shadow paging to cause a denial of
  service via a pagetable update (bsc#995792)

  - CVE-2016-7154: Use-after-free vulnerability in the FIFO event channel
  code in Xen allowed local guest OS administrators to cause a denial of
  service (host crash) and possibly execute arbitrary code or obtain
  sensitive information via an invalid guest frame number (bsc#997731)

  - CVE-2016-6836: VMWARE VMXNET3 NIC device support was leaging information
  leakage. A privileged user inside guest could have used this to leak
  host memory bytes to a guest (boo#994761)

  - CVE-2016-6888: Integer overflow in packet initialisation in VMXNET3
  device driver. A privileged user inside guest could have used this flaw
  to crash the Qemu instance resulting in DoS (bsc#994772)

  - CVE-2016-6833: Use-after-free issue in the VMWARE VMXNET3 NIC device
  support. A privileged user inside guest could have used this issue to
  crash the Qemu instance resulting in DoS (boo#994775)

  - CVE-2016-6835: Buffer overflow in the VMWARE VMXNET3 NIC device support,
  causing an OOB read access (bsc#994625)

  - CVE-2016-6834: A infinite loop during packet fragmentation in the VMWARE
  VMXNET3 NIC device support allowed privileged user inside guest to crash
  the Qemu instance resulting in DoS (bsc#994421)

  - CVE-2016-6258: The PV pagetable code in arch/x86/mm.c in Xen allowed
  local 32-bit PV guest OS administrators to gain host OS privileges by
  leveraging fast-paths for updating pagetable entries (bsc#988675)

  - CVE-2016-5403: The virtqueue_pop function in hw/virtio/virtio.c in QEMU
  allowed local guest OS administrators to cause a denial of service
  (memory consumption and QEMU process crash) by submitting requests
  without waiting for completion (boo#990923)

  - CVE-2016-6351: The esp_do_dma function in hw/scsi/esp.c, when built with
  ESP/NCR53C9x controller emulation support, allowed local guest OS
  administrators to cause a denial of service (out-of-bounds write and
  QEMU process cras ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"xen on openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.4.4_05~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.4.4_05~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.4_05~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.4.4_05~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.4_05~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.4.4_05~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.4_05~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.4_05~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.4_05_k3.16.7_42~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.4.4_05_k3.16.7_42~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-desktop", rpm:"xen-kmp-desktop~4.4.4_05_k3.16.7_42~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-desktop-debuginfo", rpm:"xen-kmp-desktop-debuginfo~4.4.4_05_k3.16.7_42~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.4_05~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.4.4_05~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.4_05~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.4.4_05~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
