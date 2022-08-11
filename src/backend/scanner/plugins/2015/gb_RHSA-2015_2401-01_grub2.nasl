###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for grub2 RHSA-2015:2401-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871479");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-11-20 06:19:53 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2015-5281");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for grub2 RHSA-2015:2401-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The grub2 packages provide version 2 of
the Grand Unified Bootloader (GRUB), a highly configurable and customizable
bootloader with modular architecture. The packages support a variety of kernel
formats, file systems, computer architectures, and hardware devices.

It was discovered that grub2 builds for EFI systems contained modules that
were not suitable to be loaded in a Secure Boot environment. An attacker
could use this flaw to circumvent the Secure Boot mechanisms and load
non-verified code. Attacks could use the boot menu if no password was set,
or the grub2 configuration file if the attacker has root privileges on the
system. (CVE-2015-5281)

This update also fixes the following bugs:

  * In one of the earlier updates, GRUB2 was modified to escape forward slash
(/) characters in several different places. In one of these places, the
escaping was unnecessary and prevented certain types of kernel command-line
arguments from being passed to the kernel correctly. With this update,
GRUB2 no longer escapes the forward slash characters in the mentioned
place, and the kernel command-line arguments work as expected. (BZ#1125404)

  * Previously, GRUB2 relied on a timing mechanism provided by legacy
hardware, but not by the Hyper-V Gen2 hypervisor, to calibrate its timer
loop. This prevented GRUB2 from operating correctly on Hyper-V Gen2.
This update modifies GRUB2 to use a different mechanism on Hyper-V Gen2 to
calibrate the timing. As a result, Hyper-V Gen2 hypervisors now work as
expected. (BZ#1150698)

  * Prior to this update, users who manually configured GRUB2 to use the
built-in GNU Privacy Guard (GPG) verification observed the following error
on boot:

    alloc magic is broken at [addr]: [value] Aborted.

Consequently, the boot failed. The GRUB2 built-in GPG verification has been
modified to no longer free the same memory twice. As a result, the
mentioned error no longer occurs. (BZ#1167977)

  * Previously, the system sometimes did not recover after terminating
unexpectedly and failed to reboot. To fix this problem, the GRUB2 packages
now enforce file synchronization when creating the GRUB2 configuration
file, which ensures that the required configuration files are written to
disk. As a result, the system now reboots successfully after crashing.
(BZ#1212114)

  * Previously, if an unconfigured network driver instance was selected and
configured when the GRUB2 bootloader was loaded on a different instance,
GRUB2 did not receive notifications of the Address Resolution Protocol
(ARP) replies. Consequently, GRUB2 failed with the following error message:

    error: timeout:  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"grub2 on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00046.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"grub2", rpm:"grub2~2.02~0.29.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"grub2-debuginfo", rpm:"grub2-debuginfo~2.02~0.29.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"grub2-efi", rpm:"grub2-efi~2.02~0.29.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"grub2-tools", rpm:"grub2-tools~2.02~0.29.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
