###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for kernel SUSE-SA:2011:008
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850159");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-02-16 14:19:17 +0100 (Wed, 16 Feb 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2010-2946", "CVE-2010-3067", "CVE-2010-3310", "CVE-2010-3442", "CVE-2010-3848", "CVE-2010-3849", "CVE-2010-3850", "CVE-2010-3873", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4081", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4158", "CVE-2010-4160", "CVE-2010-4164", "CVE-2010-4242", "CVE-2010-4258", "CVE-2010-4342", "CVE-2010-4527", "CVE-2010-4529");
  script_name("SuSE Update for kernel SUSE-SA:2011:008");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=SLES9\.0");
  script_tag(name:"impact", value:"local privilege escalation, remote denial of service");
  script_tag(name:"affected", value:"kernel on SUSE SLES 9");
  script_tag(name:"insight", value:"This patch updates the SUSE Linux Enterprise Server 9 kernel to fix
  various security issues and some bugs.

  Following security issues were fixed:
  CVE-2010-4242: The hci_uart_tty_open function in the HCI UART driver
  (drivers/bluetooth/hci_ldisc.c) in the Linux kernel did not verify
  whether the tty has a write operation, which allowed local users
  to cause a denial of service (NULL pointer dereference) via vectors
  related to the Bluetooth driver.

  CVE-2010-4527: The load_mixer_volumes function in sound/oss/soundcard.c
  in the OSS sound subsystem in the Linux kernel incorrectly expected
  that a certain name field ends with a '\0' character, which allowed
  local users to conduct buffer overflow attacks and gain privileges,
  or possibly obtain sensitive information from kernel memory, via a
  SOUND_MIXER_SETLEVELS ioctl call.

  CVE-2010-4529: Integer underflow in the irda_getsockopt function in
  net/irda/af_irda.c in the Linux kernel on platforms other than x86
  allowed local users to obtain potentially sensitive information from
  kernel heap memory via an IRLMP_ENUMDEVICES getsockopt call.

  CVE-2010-4342: The aun_incoming function in net/econet/af_econet.c in
  the Linux kernel, when Econet is enabled, allowed remote attackers
  to cause a denial of service (NULL pointer dereference and OOPS)
  by sending an Acorn Universal Networking (AUN) packet over UDP.

  CVE-2010-2946: fs/jfs/xattr.c in the Linux kernel did not properly
  handle a certain legacy format for storage of extended attributes,
  which might have allowed local users by bypass intended xattr namespace
  restrictions via an 'os2.' substring at the beginning of a name.

  CVE-2010-3848: Stack-based buffer overflow in the econet_sendmsg
  function in net/econet/af_econet.c in the Linux kernel, when an
  econet address is configured, allowed local users to gain privileges
  by providing a large number of iovec structures.

  CVE-2010-3849: The econet_sendmsg function in net/econet/af_econet.c
  in the Linux kernel, when an econet address is configured, allowed
  local users to cause a denial of service (NULL pointer dereference
  and OOPS) via a sendmsg call that specifies a NULL value for the
  remote address field.

  CVE-2010-3850: The ec_dev_ioctl function in net/econet/af_econet.c
  in the Linux kernel does not require the CAP_NET_ADMIN capability,
  which allowed local users to bypass intended access restrictions and
  configure econet addresses via an SIOCSIFADDR ioctl call.

  CVE-2010-4258: The do_exit function in kernel/exit.c in the Linux
  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLES9.0")
{

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.5~7.325", rls:"SLES9.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.5~7.325", rls:"SLES9.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.5~7.325", rls:"SLES9.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.5~7.325", rls:"SLES9.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.5~7.325", rls:"SLES9.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp", rpm:"xen-kmp~3.0.4_2.6.5_7.325~0.2", rls:"SLES9.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
