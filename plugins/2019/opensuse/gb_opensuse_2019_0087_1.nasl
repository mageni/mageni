###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2019_0087_1.nasl 13374 2019-01-31 07:19:48Z asteins $
#
# SuSE Update for zeromq openSUSE-SU-2019:0087-1 (zeromq)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.852254");
  script_version("$Revision: 13374 $");
  script_cve_id("CVE-2019-6250");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-01-31 08:19:48 +0100 (Thu, 31 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-26 04:03:40 +0100 (Sat, 26 Jan 2019)");
  script_name("SuSE Update for zeromq openSUSE-SU-2019:0087-1 (zeromq)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-01/msg00031.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zeromq'
  package(s) announced via the openSUSE-SU-2019:0087_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for zeromq fixes the following issues:

  Security issue fixed:

  - CVE-2019-6250: fix a remote execution vulnerability due to pointer
  arithmetic overflow (bsc#1121717)

  The following tracked packaging change is included:

  - boo1082318: correctly mark license files as licence instead of
  documentation.

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-87=1");

  script_tag(name:"affected", value:"zeromq on openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"libzmq5", rpm:"libzmq5~4.2.3~lp150.2.10.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libzmq5-debuginfo", rpm:"libzmq5-debuginfo~4.2.3~lp150.2.10.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zeromq-debugsource", rpm:"zeromq-debugsource~4.2.3~lp150.2.10.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zeromq-devel", rpm:"zeromq-devel~4.2.3~lp150.2.10.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zeromq-tools", rpm:"zeromq-tools~4.2.3~lp150.2.10.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zeromq-tools-debuginfo", rpm:"zeromq-tools-debuginfo~4.2.3~lp150.2.10.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
