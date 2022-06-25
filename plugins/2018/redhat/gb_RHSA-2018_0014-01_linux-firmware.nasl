###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2018_0014-01_linux-firmware.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# RedHat Update for linux-firmware RHSA-2018:0014-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812601");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-01-05 23:54:21 +0100 (Fri, 05 Jan 2018)");
  script_cve_id("CVE-2017-5715");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for linux-firmware RHSA-2018:0014-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-firmware'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The linux-firmware packages contain all of
  the firmware files that are required by various devices to operate. Security
  Fix(es): * An industry-wide issue was found in the way many modern
  microprocessor designs have implemented speculative execution of instructions (a
  commonly used performance optimization). There are three primary variants of the
  issue which differ in the way the speculative execution can be exploited.
  Variant CVE-2017-5715 triggers the speculative execution by utilizing branch
  target injection. It relies on the presence of a precisely-defined instruction
  sequence in the privileged code as well as the fact that memory accesses may
  cause allocation into the microprocessor's data cache even for speculatively
  executed instructions that never actually commit (retire). As a result, an
  unprivileged attacker could use this flaw to cross the syscall and guest/host
  boundaries and read privileged memory by conducting targeted cache side-channel
  attacks. (CVE-2017-5715) Note: This is the microcode counterpart of the
  CVE-2017-5715 kernel mitigation. Red Hat would like to thank Google Project Zero
  for reporting this issue.");
  script_tag(name:"affected", value:"linux-firmware on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2018-January/msg00012.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"iwl100-firmware", rpm:"iwl100-firmware~39.31.5.1~57.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl1000-firmware", rpm:"iwl1000-firmware~39.31.5.1~57.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl105-firmware", rpm:"iwl105-firmware~18.168.6.1~57.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl135-firmware", rpm:"iwl135-firmware~18.168.6.1~57.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl2000-firmware", rpm:"iwl2000-firmware~18.168.6.1~57.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl2030-firmware", rpm:"iwl2030-firmware~18.168.6.1~57.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl3160-firmware", rpm:"iwl3160-firmware~22.0.7.0~57.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl3945-firmware", rpm:"iwl3945-firmware~15.32.2.9~57.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl4965-firmware", rpm:"iwl4965-firmware~228.61.2.24~57.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl5000-firmware", rpm:"iwl5000-firmware~8.83.5.1_1~57.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl5150-firmware", rpm:"iwl5150-firmware~8.24.2.2~57.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl6000-firmware", rpm:"iwl6000-firmware~9.221.4.1~57.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl6000g2a-firmware", rpm:"iwl6000g2a-firmware~17.168.5.3~57.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl6000g2b-firmware", rpm:"iwl6000g2b-firmware~17.168.5.2~57.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl6050-firmware", rpm:"iwl6050-firmware~41.28.5.1~57.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl7260-firmware", rpm:"iwl7260-firmware~22.0.7.0~57.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwl7265-firmware", rpm:"iwl7265-firmware~22.0.7.0~57.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"linux-firmware", rpm:"linux-firmware~20170606~57.gitc990aae.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
