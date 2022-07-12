# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852350");
  script_version("2019-03-27T07:32:46+0000");
  script_cve_id("CVE-2018-12178", "CVE-2018-12180", "CVE-2018-3630");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-03-27 07:32:46 +0000 (Wed, 27 Mar 2019)");
  script_tag(name:"creation_date", value:"2019-03-21 09:51:09 +0100 (Thu, 21 Mar 2019)");
  script_name("SuSE Update for ovmf openSUSE-SU-2019:0348-1 (ovmf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-03/msg00029.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ovmf'
  package(s) announced via the openSUSE-SU-2019:0348_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ovmf fixes the following issues:

  Security issues fixed:

  - CVE-2018-12180: Fixed a buffer overflow in BlockIo service, which could
  lead to memory read/write overrun (bsc#1127820).

  - CVE-2018-12178: Fixed an improper DNS check upon receiving a new DNS
  packet (bsc#1127821).

  - CVE-2018-3630: Fixed a logic error in FV parsing which could allow a
  local attacker to bypass the chain of trust checks (bsc#1127822).

  This update was imported from the SUSE:SLE-12-SP3:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-348=1");

  script_tag(name:"affected", value:"ovmf on openSUSE Leap 42.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap42.3")
{

  if((res = isrpmvuln(pkg:"ovmf-2017+git1492060560.b6d11d7c46", rpm:"ovmf-2017+git1492060560.b6d11d7c46~16.1", rls:"openSUSELeap42.3")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"ovmf-tools-2017+git1492060560.b6d11d7c46", rpm:"ovmf-tools-2017+git1492060560.b6d11d7c46~16.1", rls:"openSUSELeap42.3")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"qemu-ovmf-x86_64-debug-2017+git1492060560.b6d11d7c46", rpm:"qemu-ovmf-x86_64-debug-2017+git1492060560.b6d11d7c46~16.1", rls:"openSUSELeap42.3")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"qemu-ovmf-ia32-2017+git1492060560.b6d11d7c46", rpm:"qemu-ovmf-ia32-2017+git1492060560.b6d11d7c46~16.1", rls:"openSUSELeap42.3")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"qemu-ovmf-x86_64-2017+git1492060560.b6d11d7c46", rpm:"qemu-ovmf-x86_64-2017+git1492060560.b6d11d7c46~16.1", rls:"openSUSELeap42.3")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if(__pkg_match) exit(99);
  exit(0);
}
