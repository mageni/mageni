###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_021.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for kernel SUSE-SA:2007:021
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
tag_insight = "The Linux kernel was updated to fix the security problems listed below.

  This advisory is for the bugs already announced for SUSE Linux
  Enterprise 10 and SUSE Linux 10.1 in SUSE-SA:2007:018.

  The packages associated with this update were already released 1
  week ago.

  Please note that bootloader handling in openSUSE 10.2 has changed and
  now creates new entries for updated kernels and make those the default.

  We also had reports of the update breaking the bootloader
  configuration, and apologize for the inconveniences caused. We are
  investigating those problems and hope to release an update to fix
  the bootloader handling code.

  If you are manually adapting /boot/grub/menu.lst, please review this
  file after the update.

  - CVE-2006-2936: The ftdi_sio driver allowed local users to cause a
  denial of service (memory consumption) by writing more data to the
  serial port than the hardware can handle, which causes the data
  to be queued. This requires this driver to be loaded, which only
  happens if such a device is plugged in.

  - CVE-2006-5751: An integer overflow in the networking bridge ioctl
  starting with Kernel 2.6.7 could be used by local attackers to
  overflow kernel memory buffers and potentially escalate privileges.

  - CVE-2006-6106: Multiple buffer overflows in the cmtp_recv_interopmsg
  function in the Bluetooth driver (net/bluetooth/cmtp/capi.c) in the
  Linux kernel allowed remote attackers to cause a denial of service
  (crash) and possibly execute arbitrary code via CAPI messages with
  a large value for the length of the (1) manu (manufacturer) or (2)
  serial (serial number) field.

  - CVE-2006-5749: The isdn_ppp_ccp_reset_alloc_state function in
  drivers/isdn/isdn_ppp.c in the Linux kernel does not call the
  init_timer function for the ISDN PPP CCP reset state timer, which
  has unknown attack vectors and results in a system crash.

  - CVE-2006-5753: Unspecified vulnerability in the listxattr system
  call in Linux kernel, when a &quot;bad inode&quot; is present, allows local
  users to cause a denial of service (data corruption) and possibly
  gain privileges.

  - CVE-2007-0006: The key serial number collision avoidance code in
  the key_alloc_serial function allows local users to cause a denial
  of service (crash) via vectors that trigger a null dereference.

  - CVE-2007-0772: A remote denial of service problem on NFSv2 mounts
  with ACL enabled was fixed.

  Furthermore, openSUSE 10.2 catches up to the mainline kernel, version
  2.6.18.8, and contains a large number of additional fixes for non
  security bugs.";

tag_impact = "remote denial of service";
tag_affected = "kernel on openSUSE 10.2";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.304407");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2006-2936", "CVE-2006-5749", "CVE-2006-5751", "CVE-2006-5753", "CVE-2006-6106", "CVE-2007-0006", "CVE-2007-0772");
  script_name( "SuSE Update for kernel SUSE-SA:2007:021");

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

if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"ivtv-kmp-bigsmp", rpm:"ivtv-kmp-bigsmp~0.8.0_2.6.18.8_0.1~10", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ivtv-kmp-debug", rpm:"ivtv-kmp-debug~0.8.0_2.6.18.8_0.1~10", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ivtv-kmp-default", rpm:"ivtv-kmp-default~0.8.0_2.6.18.8_0.1~10", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ivtv-kmp-xen", rpm:"ivtv-kmp-xen~0.8.0_2.6.18.8_0.1~10", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ivtv-kmp-xenpae", rpm:"ivtv-kmp-xenpae~0.8.0_2.6.18.8_0.1~10", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.18.8~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.18.8~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.18.8~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.18.8~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18.8~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.18.8~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kmp-bigsmp", rpm:"lirc-kmp-bigsmp~0.8.0_2.6.18.8_0.1~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kmp-default", rpm:"lirc-kmp-default~0.8.0_2.6.18.8_0.1~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kmp-xenpae", rpm:"lirc-kmp-xenpae~0.8.0_2.6.18.8_0.1~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quickcam-kmp-bigsmp", rpm:"quickcam-kmp-bigsmp~0.6.4_2.6.18.8_0.1~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quickcam-kmp-default", rpm:"quickcam-kmp-default~0.6.4_2.6.18.8_0.1~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"usbvision-kmp-bigsmp", rpm:"usbvision-kmp-bigsmp~0.9.8.3_2.6.18.8_0.1~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"usbvision-kmp-debug", rpm:"usbvision-kmp-debug~0.9.8.3_2.6.18.8_0.1~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"usbvision-kmp-default", rpm:"usbvision-kmp-default~0.9.8.3_2.6.18.8_0.1~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"usbvision-kmp-xen", rpm:"usbvision-kmp-xen~0.9.8.3_2.6.18.8_0.1~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"usbvision-kmp-xenpae", rpm:"usbvision-kmp-xenpae~0.9.8.3_2.6.18.8_0.1~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
