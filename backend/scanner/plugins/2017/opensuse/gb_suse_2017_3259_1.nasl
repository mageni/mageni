###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_3259_1.nasl 13941 2019-02-28 14:35:50Z cfischer $
#
# SuSE Update for OBS toolchain openSUSE-SU-2017:3259-1 (OBS toolchain)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851662");
  script_version("$Revision: 13941 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-28 15:35:50 +0100 (Thu, 28 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-12-10 07:43:31 +0100 (Sun, 10 Dec 2017)");
  script_cve_id("CVE-2010-4226", "CVE-2017-14804", "CVE-2017-9274");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for OBS toolchain openSUSE-SU-2017:3259-1 (OBS toolchain)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'OBS toolchain'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This OBS toolchain update fixes the following issues:

  Package 'build':

  - CVE-2010-4226: force use of bsdtar for VMs (bnc#665768)

  - CVE-2017-14804: Improve file name check extractbuild (bsc#1069904)

  - switch baselibs scheme for debuginfo packages from foo-debuginfo-32bit
  to foo-32bit-debuginfo (fate#323217)

  Package 'obs-service-source_validator':

  - CVE-2017-9274: Don't use rpmbuild to extract sources, patches etc. from
  a spec (bnc#938556).

  - Update to version 0.7

  - use spec_query instead of output_versions using the specfile parser from
  the build package (boo#1059858)

  Package 'osc':

  - update to version 0.162.0

  - add Recommends: ca-certificates to enable TLS verification without
  manually installing them. (bnc#1061500)

  This update was imported from the SUSE:SLE-12:Update update project.");
  script_tag(name:"affected", value:"OBS toolchain on openSUSE Leap 42.3, openSUSE Leap 42.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.3)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"build-20171128", rpm:"build-20171128~2.6.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"build-initvm-i586-20171128", rpm:"build-initvm-i586-20171128~2.6.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"build-initvm-x86_64-20171128", rpm:"build-initvm-x86_64-20171128~2.6.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"build-mkbaselibs-20171128", rpm:"build-mkbaselibs-20171128~2.6.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"build-mkdrpms-20171128", rpm:"build-mkdrpms-20171128~2.6.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"obs-service-source_validator", rpm:"obs-service-source_validator~0.7~13.6.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"osc", rpm:"osc~0.162.0~7.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"build-20171128", rpm:"build-20171128~5.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"build-initvm-i586-20171128", rpm:"build-initvm-i586-20171128~5.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"build-initvm-x86_64-20171128", rpm:"build-initvm-x86_64-20171128~5.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"build-mkbaselibs-20171128", rpm:"build-mkbaselibs-20171128~5.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"build-mkdrpms-20171128", rpm:"build-mkdrpms-20171128~5.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"obs-service-source_validator", rpm:"obs-service-source_validator~0.7~16.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"osc", rpm:"osc~0.162.0~10.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
