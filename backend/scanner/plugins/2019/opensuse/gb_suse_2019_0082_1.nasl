###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2019_0082_1.nasl 13316 2019-01-28 07:41:51Z asteins $
#
# SuSE Update for ntpsec openSUSE-SU-2019:0082-1 (ntpsec)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852249");
  script_version("$Revision: 13316 $");
  script_cve_id("CVE-2019-6442", "CVE-2019-6443", "CVE-2019-6444", "CVE-2019-6445");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-01-28 08:41:51 +0100 (Mon, 28 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-24 04:04:09 +0100 (Thu, 24 Jan 2019)");
  script_name("SuSE Update for ntpsec openSUSE-SU-2019:0082-1 (ntpsec)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-01/msg00030.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntpsec'
  package(s) announced via the openSUSE-SU-2019:0082_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ntpsec to version 1.1.3 fixes the following issues:

  Security issues fixed:

  - CVE-2019-6442: Fixed a out of bounds write via a malformed config
  request (boo#1122132)

  - CVE-2019-6443: Fixed a stack-based buffer over-read in the ctl_getitem
  function (boo#1122144)

  - CVE-2019-6444: Fixed a stack-based buffer over-read in the
  process_control function (boo#1122134)

  - CVE-2019-6445: Fixed a NULL pointer dereference in the ctl_getitem
  function (boo#1122131)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-82=1");

  script_tag(name:"affected", value:"ntpsec on openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"ntpsec", rpm:"ntpsec~1.1.3~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntpsec-debuginfo", rpm:"ntpsec-debuginfo~1.1.3~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntpsec-debugsource", rpm:"ntpsec-debugsource~1.1.3~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntpsec-utils", rpm:"ntpsec-utils~1.1.3~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-ntp", rpm:"python3-ntp~1.1.3~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-ntp-debuginfo", rpm:"python3-ntp-debuginfo~1.1.3~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
