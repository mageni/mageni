###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_2306_1.nasl 14110 2019-03-12 09:28:23Z cfischer $
#
# SuSE Update for postgresql93 openSUSE-SU-2017:2306-1 (postgresql93)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851603");
  script_version("$Revision: 14110 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 10:28:23 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-08-31 07:46:26 +0200 (Thu, 31 Aug 2017)");
  script_cve_id("CVE-2017-7546", "CVE-2017-7547", "CVE-2017-7548");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for postgresql93 openSUSE-SU-2017:2306-1 (postgresql93)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql93'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Postgresql93 was updated to 9.3.18 to fix the following issues:

  * CVE-2017-7547: Further restrict visibility of
  pg_user_mappings.umoptions, to protect passwords stored as user mapping
  options. (bsc#1051685)

  * CVE-2017-7546: Disallow empty passwords in all password-based
  authentication methods. (bsc#1051684)

  * CVE-2017-7548: lo_put() function ignores ACLs. (bsc#1053259)

  The changelog for the release is linked in the references.

  This update was imported from the SUSE:SLE-12:Update update project.");
  script_tag(name:"affected", value:"postgresql93 on openSUSE Leap 42.3, openSUSE Leap 42.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.3)");

  script_xref(name:"URL", value:"https://www.postgresql.org/docs/9.3/static/release-9-3-18.html");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"postgresql93-devel", rpm:"postgresql93-devel~9.3.18~5.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-devel-debuginfo", rpm:"postgresql93-devel-debuginfo~9.3.18~5.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-libs-debugsource", rpm:"postgresql93-libs-debugsource~9.3.18~5.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-docs", rpm:"postgresql93-docs~9.3.18~5.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93", rpm:"postgresql93~9.3.18~5.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-contrib", rpm:"postgresql93-contrib~9.3.18~5.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-contrib-debuginfo", rpm:"postgresql93-contrib-debuginfo~9.3.18~5.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-debuginfo", rpm:"postgresql93-debuginfo~9.3.18~5.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-debugsource", rpm:"postgresql93-debugsource~9.3.18~5.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-plperl", rpm:"postgresql93-plperl~9.3.18~5.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-plperl-debuginfo", rpm:"postgresql93-plperl-debuginfo~9.3.18~5.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-plpython", rpm:"postgresql93-plpython~9.3.18~5.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-plpython-debuginfo", rpm:"postgresql93-plpython-debuginfo~9.3.18~5.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-pltcl", rpm:"postgresql93-pltcl~9.3.18~5.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-pltcl-debuginfo", rpm:"postgresql93-pltcl-debuginfo~9.3.18~5.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-server", rpm:"postgresql93-server~9.3.18~5.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-server-debuginfo", rpm:"postgresql93-server-debuginfo~9.3.18~5.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-test", rpm:"postgresql93-test~9.3.18~5.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"postgresql93-devel", rpm:"postgresql93-devel~9.3.18~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-devel-debuginfo", rpm:"postgresql93-devel-debuginfo~9.3.18~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-libs-debugsource", rpm:"postgresql93-libs-debugsource~9.3.18~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93", rpm:"postgresql93~9.3.18~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-contrib", rpm:"postgresql93-contrib~9.3.18~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-contrib-debuginfo", rpm:"postgresql93-contrib-debuginfo~9.3.18~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-debuginfo", rpm:"postgresql93-debuginfo~9.3.18~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-debugsource", rpm:"postgresql93-debugsource~9.3.18~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-plperl", rpm:"postgresql93-plperl~9.3.18~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-plperl-debuginfo", rpm:"postgresql93-plperl-debuginfo~9.3.18~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-plpython", rpm:"postgresql93-plpython~9.3.18~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-plpython-debuginfo", rpm:"postgresql93-plpython-debuginfo~9.3.18~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-pltcl", rpm:"postgresql93-pltcl~9.3.18~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-pltcl-debuginfo", rpm:"postgresql93-pltcl-debuginfo~9.3.18~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-server", rpm:"postgresql93-server~9.3.18~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-server-debuginfo", rpm:"postgresql93-server-debuginfo~9.3.18~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-test", rpm:"postgresql93-test~9.3.18~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-docs", rpm:"postgresql93-docs~9.3.18~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
