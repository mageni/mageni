###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_059.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for kernel SUSE-SA:2007:059
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "The Linux kernel on openSUSE 10.3 was updated to fix a critical
  locking problem in the reiserfs code which lead to process deadlocks.

  This kernel update also fixes the following two security problems:

  - CVE-2006-6058: A local denial of service when mounting
  MINIX filesystems was fixed.

  - CVE-2007-4997: A 2 byte buffer underflow in the ieee80211 stack
  was fixed, which might be used by attackers in the
  local WLAN reach to crash the machine.

  and the following non security bugs:

  -  Kernel update to 2.6.22.12
  including fixes for:
  genirq, x86_64, Infiniband, networking, hwmon, device removal bug
  [#332612]
  -  patches.drivers/alsa-hdsp-zero-division:
  hdsp - Fix zero division (mainline: 2.6.24-rc1)
  -  patches.drivers/libata-ata_piix-properly_terminate_DMI_system_list:
  Fix improperly terminated array
  -  patches.rt/patch-2.6.22.1-rt4.openSUSE:
  updated existing patch (RT only)
  -  patches.drivers/alsa-hda-robust-probe:
  hda-intel - Improve HD-audio codec probing robustness  [#172330]
  -  patches.drivers/alsa-hda-probe-blacklist:
  hda-intel - Add probe_mask blacklist  [#172330]
  -  patches.fixes/megaraid_mbox-dell-cerc-support:
  Dell CERC support for megaraid_mbox  [#267134]
  -  patches.suse/reiserfs-use-reiserfs_error.diff:
  updated existing patch  [#299604]
  -  patches.arch/acpi_gpe_suspend_cleanup-fix.patch:
  ACPI: Call acpi_enable_wakeup_device at power_off (updated)
  [#299882]
  -  patches.suse/ocfs2-15-fix-heartbeat-write.diff:
  Fix heartbeat block writing  [#300730]
  -  patches.suse/ocfs2-14-fix-notifier-hang.diff:
  Fix kernel hang during cluster initialization  [#300730]
  -  patches.arch/acpi_autoload_bay.patch:
  updated existing patch  [#302482]
  -  patches.suse/zc0301_not_claim_logitech_quickcamera.diff:
  stop the zc0301 driver from claiming the Logitech QuickCam
  [#307055]
  -  patches.fixes/aux-at_vector_size.patch:
  Fixed kernel auxv vector overflow in some binfmt_misc cases
  [#310037]
  -  patches.fixes/nfs-name-len-limit:
  NFS: Fix an Oops in encode_lookup()  [#325913]
  -  patches.arch/acpi_lid-resume.patch:
  ACPI: button: send initial lid state after add and resume
  [#326814]
  -  patches.fixes/remove-transparent-bridge-sizing:
  PCI: remove transparent bridge sizing  [#331027]
  -  patches.fi ... 

  Description truncated, for more information please check the Reference URL";

tag_impact = "remote denial of service";
tag_affected = "kernel on openSUSE 10.3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.305679");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2006-6058", "CVE-2007-4997");
  script_name( "SuSE Update for kernel SUSE-SA:2007:059");

  script_tag(name:"summary", value:"Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE10.3")
{

  if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.22.12~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.22.12~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.22.12~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.22.12~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.22.12~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.22.12~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.22.12~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
