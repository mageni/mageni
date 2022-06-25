###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_4240_1.nasl 12882 2018-12-27 07:14:01Z santu $
#
# SuSE Update for ovmf openSUSE-SU-2018:4240-1 (ovmf)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852208");
  script_version("$Revision: 12882 $");
  script_cve_id("CVE-2017-5731", "CVE-2017-5732", "CVE-2017-5733", "CVE-2017-5734",
                "CVE-2017-5735", "CVE-2018-3613");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-27 08:14:01 +0100 (Thu, 27 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-23 04:01:25 +0100 (Sun, 23 Dec 2018)");
  script_name("SuSE Update for ovmf openSUSE-SU-2018:4240-1 (ovmf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-12/msg00055.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ovmf'
  package(s) announced via the openSUSE-SU-2018:4240_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ovmf fixes the following issues:

  Security issues fixed:

  - CVE-2018-3613: Fixed AuthVariable Timestamp zeroing issue on
  APPEND_WRITE (bsc#1115916).

  - CVE-2017-5731: Fixed privilege escalation via processing of malformed
  files in TianoCompress.c (bsc#1115917).

  - CVE-2017-5732: Fixed privilege escalation via processing of malformed
  files in BaseUefiDecompressLib.c (bsc#1115917).

  - CVE-2017-5733: Fixed privilege escalation via heap-based buffer overflow
  in MakeTable() function (bsc#1115917).

  - CVE-2017-5734: Fixed privilege escalation via stack-based buffer
  overflow in MakeTable() function (bsc#1115917).

  - CVE-2017-5735: Fixed privilege escalation via heap-based buffer overflow
  in Decode() function (bsc#1115917).

  Non security issues fixed:

  - Fixed an issue with the default owner of PK/KEK/db/dbx and make the
  auto-enrollment only happen at the very first time. (bsc#1117998)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1590=1");

  script_tag(name:"affected", value:"ovmf on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"ovmf", rpm:"ovmf~2017+git1510945757.b2662641d5~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ovmf-tools", rpm:"ovmf-tools~2017+git1510945757.b2662641d5~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-ovmf-x86", rpm:"qemu-ovmf-x86~64~debug~2017+git1510945757.b2662641d5~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-ovmf-ia32", rpm:"qemu-ovmf-ia32~2017+git1510945757.b2662641d5~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-ovmf-x86", rpm:"qemu-ovmf-x86~64~2017+git1510945757.b2662641d5~lp150.4.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
