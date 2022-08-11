###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_063.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for kernel SUSE-SA:2007:063
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
tag_insight = "The openSUSE 10.3 kernel was updated to fix various problems, both
  security and non-security bugs.

  It fixes the following security problems:

  - CVE-2007-5501: The tcp_sacktag_write_queue function in
  net/ipv4/tcp_input.c allows remote attackers to cause a denial of
  service (crash) via crafted TCP ACK responses that trigger a NULL
  pointer dereference.

  Please note that this problem only affects only Linux Kernels
  starting with 2.6.21, so only the openSUSE 10.3 code base is
  affected.

  - CVE-2007-5500: A buggy condition in the ptrace attach logic can be
  used by local attackers to hang the machine.

  - CVE-2007-5904: Multiple buffer overflows in CIFS VFS allows remote
  attackers to cause a denial of service (crash) and possibly execute
  arbitrary code via long SMB responses that trigger the overflows
  in the SendReceive function.

  This requires the attacker to set up a malicious Samba/CIFS server
  and getting the client to connect to it, so is very likely restricted
  to the site network.

  Also the exploitability of this problem not known.

  and the following non security bugs:

  - Kernel update to 2.6.22.13
  (includes the fixes for CVE-2007-5501 described
  above)

  - patches.fixes/input-add-ms-vm-to-noloop.patch:
  add i8042.noloop quirk for Microsoft Virtual Machine  [#297546]

  - patches.fixes/mac80211_fix_scan.diff:
  Make per-SSID scanning work  [#299598] [#327684]

  This should enhance the hidden ESSID scanning problems with the
  newer mac80211 wireless drivers.

  This also required a release of all the mac80211 KMP packages.

  - patches.drivers/kobil_sct_backport.patch:
  Fix segfault for Kobil USB Plus card readers  [#327664]

  - patches.arch/acpi_thermal_passive_blacklist.patch:
  Avoid critical temp shutdowns on specific ThinkPad T4x(p) and R40
  [#333043]

  - patches.fixes/microtek_hal.diff:
  Make the microtek driver work with HAL  [#339743]

  - patches.fixes/pci-fix-unterminated-pci_device_id-lists:
  fix unterminated pci_device_id lists  [#340527]

  - patches.fixes/nfsacl-retval.diff: knfsd:
  fix spurious EINVAL errors on first access of new filesystem [#340873]";

tag_impact = "remote denial of service";
tag_affected = "kernel on openSUSE 10.3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.304498");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2007-5500", "CVE-2007-5501", "CVE-2007-5904");
  script_name( "SuSE Update for kernel SUSE-SA:2007:063");

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

  if ((res = isrpmvuln(pkg:"adm8211-kmp-bigsmp-20070720", rpm:"adm8211-kmp-bigsmp-20070720~2.6.22.13_0.2~2.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"adm8211-kmp-debug-20070720", rpm:"adm8211-kmp-debug-20070720~2.6.22.13_0.2~2.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"adm8211-kmp-default-20070720", rpm:"adm8211-kmp-default-20070720~2.6.22.13_0.2~2.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"adm8211-kmp-xen-20070720", rpm:"adm8211-kmp-xen-20070720~2.6.22.13_0.2~2.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"adm8211-kmp-xenpae-20070720", rpm:"adm8211-kmp-xenpae-20070720~2.6.22.13_0.2~2.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwlwifi-kmp-bigsmp", rpm:"iwlwifi-kmp-bigsmp~1.1.0_2.6.22.13_0.2~1.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwlwifi-kmp-debug", rpm:"iwlwifi-kmp-debug~1.1.0_2.6.22.13_0.2~1.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwlwifi-kmp-default", rpm:"iwlwifi-kmp-default~1.1.0_2.6.22.13_0.2~1.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwlwifi-kmp-xen", rpm:"iwlwifi-kmp-xen~1.1.0_2.6.22.13_0.2~1.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwlwifi-kmp-xenpae", rpm:"iwlwifi-kmp-xenpae~1.1.0_2.6.22.13_0.2~1.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.22.13~0.3", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.22.13~0.3", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.22.13~0.3", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~2.6.22.13~0.3", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~2.6.22.13~0.3", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.22.13~0.3", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.22.13~0.3", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.22.13~0.3", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.22.13~0.3", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"p54-kmp-bigsmp-20070806", rpm:"p54-kmp-bigsmp-20070806~2.6.22.13_0.2~2.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"p54-kmp-debug-20070806", rpm:"p54-kmp-debug-20070806~2.6.22.13_0.2~2.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"p54-kmp-default-20070806", rpm:"p54-kmp-default-20070806~2.6.22.13_0.2~2.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"p54-kmp-xen-20070806", rpm:"p54-kmp-xen-20070806~2.6.22.13_0.2~2.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"p54-kmp-xenpae-20070806", rpm:"p54-kmp-xenpae-20070806~2.6.22.13_0.2~2.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rt2x00-kmp-bigsmp", rpm:"rt2x00-kmp-bigsmp~2.0.6+git20070816_2.6.22.13_0.2~1.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rt2x00-kmp-debug", rpm:"rt2x00-kmp-debug~2.0.6+git20070816_2.6.22.13_0.2~1.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rt2x00-kmp-default", rpm:"rt2x00-kmp-default~2.0.6+git20070816_2.6.22.13_0.2~1.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rt2x00-kmp-xen", rpm:"rt2x00-kmp-xen~2.0.6+git20070816_2.6.22.13_0.2~1.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rt2x00-kmp-xenpae", rpm:"rt2x00-kmp-xenpae~2.0.6+git20070816_2.6.22.13_0.2~1.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rtl8187-kmp-bigsmp-20070806", rpm:"rtl8187-kmp-bigsmp-20070806~2.6.22.13_0.2~1.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rtl8187-kmp-debug-20070806", rpm:"rtl8187-kmp-debug-20070806~2.6.22.13_0.2~1.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rtl8187-kmp-default-20070806", rpm:"rtl8187-kmp-default-20070806~2.6.22.13_0.2~1.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rtl8187-kmp-xen-20070806", rpm:"rtl8187-kmp-xen-20070806~2.6.22.13_0.2~1.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rtl8187-kmp-xenpae-20070806", rpm:"rtl8187-kmp-xenpae-20070806~2.6.22.13_0.2~1.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
