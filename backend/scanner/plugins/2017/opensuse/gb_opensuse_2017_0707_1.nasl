###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_0707_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for qemu openSUSE-SU-2017:0707-1 (qemu)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851524");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-03-17 06:32:47 +0100 (Fri, 17 Mar 2017)");
  script_cve_id("CVE-2016-10028", "CVE-2016-10029", "CVE-2016-10155", "CVE-2016-9921",
                "CVE-2016-9922", "CVE-2017-2615", "CVE-2017-2620", "CVE-2017-5525",
                "CVE-2017-5526", "CVE-2017-5552", "CVE-2017-5578", "CVE-2017-5667",
                "CVE-2017-5856", "CVE-2017-5857", "CVE-2017-5898");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for qemu openSUSE-SU-2017:0707-1 (qemu)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for qemu fixes several issues.

  These security issues were fixed:

  - CVE-2017-5898: The CCID Card device emulator support was vulnerable to
  an integer overflow flaw allowing a privileged user to crash the Qemu
  process on the host resulting in DoS (bsc#1023907).

  - CVE-2017-5857: The Virtio GPU Device emulator support was vulnerable to
  a host memory leakage issue allowing a guest user to leak host memory
  resulting in DoS (bsc#1023073).

  - CVE-2017-2620: In CIRRUS_BLTMODE_MEMSYSSRC mode the bitblit copy routine
  cirrus_bitblt_cputovideo failed to check the memory region, allowing for
  an out-of-bounds write that allows for privilege escalation (bsc#1024972)

  - CVE-2017-2615: An error in the bitblt copy operation could have allowed
  a malicious guest administrator to cause an out of bounds memory access,
  possibly leading to information disclosure
  or privilege escalation (bsc#1023004)

  - CVE-2017-5856: The MegaRAID SAS 8708EM2 Host Bus Adapter emulation
  support was vulnerable to a memory leakage issue allowing a privileged
  user to leak host memory resulting in DoS (bsc#1023053)

  - CVE-2016-9921: The Cirrus CLGD 54xx VGA Emulator support was vulnerable
  to a divide by zero issue while copying VGA data. A privileged user
  inside guest could have used this flaw to crash the process instance on
  the host, resulting in DoS (bsc#1014702)

  - CVE-2016-9922: The Cirrus CLGD 54xx VGA Emulator support was vulnerable
  to a divide by zero issue while copying VGA data. A privileged user
  inside guest could have used this flaw to crash the process instance on
  the host, resulting in DoS (bsc#1014702)

  - CVE-2016-10029: The Virtio GPU Device emulator support was vulnerable to
  an OOB read issue allowing a guest user to crash the Qemu process
  instance resulting in Dos (bsc#1017081).

  - CVE-2016-10028: The Virtio GPU Device emulator support was vulnerable to
  an out of bounds memory access issue allowing a guest user to crash the
  Qemu process instance on a host, resulting in DoS (bsc#1017084).

  - CVE-2016-10155: The virtual hardware watchdog 'wdt_i6300esb' was
  vulnerable to a memory leakage issue allowing a privileged user to cause
  a DoS and/or potentially crash the Qemu process on the host (bsc#1021129)

  - CVE-2017-5552: The Virtio GPU Device emulator support was vulnerable to
  a memory leakage issue allowing a guest user to leak host memory
  resulting in DoS (bsc#1021195).

  - CVE-2017-5578: The Virtio GPU Device emulator support was vulnerable to
  a memory leakage issue allowing a guest user to leak host memory
  resulting in DoS (bsc#1021481 ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"qemu on openSUSE Leap 42.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-arm", rpm:"qemu-arm~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-arm-debuginfo", rpm:"qemu-arm-debuginfo~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-curl-debuginfo", rpm:"qemu-block-curl-debuginfo~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-dmg", rpm:"qemu-block-dmg~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-dmg-debuginfo", rpm:"qemu-block-dmg-debuginfo~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-iscsi", rpm:"qemu-block-iscsi~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-iscsi-debuginfo", rpm:"qemu-block-iscsi-debuginfo~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-ssh-debuginfo", rpm:"qemu-block-ssh-debuginfo~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-debugsource", rpm:"qemu-debugsource~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-extra", rpm:"qemu-extra~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-extra-debuginfo", rpm:"qemu-extra-debuginfo~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-guest-agent-debuginfo", rpm:"qemu-guest-agent-debuginfo~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-linux-user", rpm:"qemu-linux-user~2.6.2~29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-linux-user-debuginfo", rpm:"qemu-linux-user-debuginfo~2.6.2~29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-linux-user-debugsource", rpm:"qemu-linux-user-debugsource~2.6.2~29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-ppc-debuginfo", rpm:"qemu-ppc-debuginfo~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-s390-debuginfo", rpm:"qemu-s390-debuginfo~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-testsuite", rpm:"qemu-testsuite~2.6.2~29.8", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-tools-debuginfo", rpm:"qemu-tools-debuginfo~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-x86-debuginfo", rpm:"qemu-x86-debuginfo~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-rbd-debuginfo", rpm:"qemu-block-rbd-debuginfo~2.6.2~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.9.1~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-sgabios-8", rpm:"qemu-sgabios-8~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.9.1~29.4", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
