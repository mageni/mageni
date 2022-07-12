###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_4181_1.nasl 13561 2019-02-11 07:33:41Z mmartin $
#
# SuSE Update for go1.11 openSUSE-SU-2018:4181-1 (go1.11)
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
  script_oid("1.3.6.1.4.1.25623.1.0.814577");
  script_version("$Revision: 13561 $");
  script_cve_id("CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 08:33:41 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-12-20 07:33:43 +0100 (Thu, 20 Dec 2018)");
  script_name("SuSE Update for go1.11 openSUSE-SU-2018:4181-1 (go1.11)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.3|openSUSELeap15\.0)");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-12/msg00051.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.11'
  package(s) announced via the openSUSE-SU-2018:4181_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This new package for go1.11 fixes the following issues:

  Security issues fixed:

  - CVE-2018-16873: Fixed a remote code execution in go get, when executed
  with the -u flag (bsc#1118897)

  - CVE-2018-16874: Fixed an arbitrary filesystem write in go get, which
  could lead to code execution (bsc#1118898)

  - CVE-2018-16875: Fixed a Denial of Service in the crypto/x509 package
  during certificate chain validation(bsc#1118899)

  Non-security issues fixed:

  - Fixed build error with PIE linker flags on ppc64le (bsc#1113978
  bsc#1098017)

  - Make profile.d/go.sh no longer set GOROOT=, in order to make switching
  between versions no longer break. This ends up removing the need for
  go.sh entirely (because GOPATH is also set automatically) (bsc#1119634)

  The following tracked regression fix is included:

  - Fix a regression that broke go get for import path patterns containing
  '...' (bsc#1119706)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1572=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1572=1");

  script_tag(name:"affected", value:"go1.11 on openSUSE Leap 42.3, openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"go1.11", rpm:"go1.11~1.11.4~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"go1.11-doc", rpm:"go1.11-doc~1.11.4~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"go1.11-race", rpm:"go1.11-race~1.11.4~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"go1.11", rpm:"go1.11~1.11.4~lp150.2.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"go1.11-doc", rpm:"go1.11-doc~1.11.4~lp150.2.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"go1.11-race", rpm:"go1.11-race~1.11.4~lp150.2.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
