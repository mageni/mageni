###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2019_0050_1.nasl 13427 2019-02-04 08:52:52Z mmartin $
#
# SuSE Update for aria2 openSUSE-SU-2019:0050-1 (aria2)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852235");
  script_version("$Revision: 13427 $");
  script_cve_id("CVE-2019-3500");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-04 09:52:52 +0100 (Mon, 04 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-14 04:00:47 +0100 (Mon, 14 Jan 2019)");
  script_name("SuSE Update for aria2 openSUSE-SU-2019:0050-1 (aria2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.3|openSUSELeap15\.0)");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-01/msg00016.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'aria2'
  package(s) announced via the openSUSE-SU-2019:0050_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for aria2 fixes the following security issue:

  - CVE-2019-3500: Metadata and potential password leaks via --log=
  (boo#1120488)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-50=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-50=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2019-50=1");

  script_tag(name:"affected", value:"aria2 on openSUSE Leap 42.3, openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"aria2", rpm:"aria2~1.24.0~4.4.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"aria2-debuginfo", rpm:"aria2-debuginfo~1.24.0~4.4.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"aria2-debugsource", rpm:"aria2-debugsource~1.24.0~4.4.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"aria2-devel", rpm:"aria2-devel~1.24.0~4.4.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libaria2-0", rpm:"libaria2-0~1.24.0~4.4.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libaria2-0-debuginfo", rpm:"libaria2-0-debuginfo~1.24.0~4.4.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"aria2-lang", rpm:"aria2-lang~1.24.0~4.4.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"aria2", rpm:"aria2~1.33.1~lp150.2.4.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"aria2-debuginfo", rpm:"aria2-debuginfo~1.33.1~lp150.2.4.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"aria2-debugsource", rpm:"aria2-debugsource~1.33.1~lp150.2.4.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"aria2-devel", rpm:"aria2-devel~1.33.1~lp150.2.4.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libaria2-0", rpm:"libaria2-0~1.33.1~lp150.2.4.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libaria2-0-debuginfo", rpm:"libaria2-0-debuginfo~1.33.1~lp150.2.4.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"aria2-lang", rpm:"aria2-lang~1.33.1~lp150.2.4.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
