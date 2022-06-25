###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_0578_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for postgresql94 openSUSE-SU-2016:0578-1 (postgresql94)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851218");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-03-01 11:08:53 +0530 (Tue, 01 Mar 2016)");
  script_cve_id("CVE-2007-4772", "CVE-2016-0766", "CVE-2016-0773");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for postgresql94 openSUSE-SU-2016:0578-1 (postgresql94)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql94'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for postgresql94 fixes the following issues:

  - Security and bugfix release 9.4.6:

  * *** IMPORTANT *** Users of version 9.4 will need to reindex any
  jsonb_path_ops indexes they have created, in order to fix a persistent
  issue with missing index entries.

  * Fix infinite loops and buffer-overrun problems in regular expressions
  (CVE-2016-0773, bsc#966436).

  * Fix regular-expression compiler to handle loops of constraint arcs
  (CVE-2007-4772).

  * Prevent certain PL/Java parameters from being set by non-superusers
  (CVE-2016-0766, bsc#966435).

  * Fix many issues in pg_dump with specific object types

  * Prevent over-eager pushdown of HAVING clauses for GROUPING SETS

  * Fix deparsing error with ON CONFLICT ... WHERE clauses

  * Fix tableoid errors for postgres_fdw

  * Prevent floating-point exceptions in pgbench

  * Make \det search Foreign Table names consistently

  * Fix quoting of domain constraint names in pg_dump

  * Prevent putting expanded objects into Const nodes

  * Allow compile of PL/Java on Windows

  * Fix 'unresolved symbol' errors in PL/Python execution

  * Allow Python2 and Python3 to be used in the same database

  * Add support for Python 3.5 in PL/Python

  * Fix issue with subdirectory creation during initdb

  * Make pg_ctl report status correctly on Windows

  * Suppress confusing error when using pg_receivexlog with older servers

  * Multiple documentation corrections and additions

  * Fix erroneous hash calculations in gin_extract_jsonb_path()

  - PL/Perl still needs to be linked with rpath, so that it can find
  libperl.so at runtime. bsc#578053, postgresql-plperl-keep-rpath.patch

  This update was imported from the SUSE:SLE-12:Update update project.");
  script_tag(name:"affected", value:"postgresql94 on openSUSE Leap 42.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libecpg6-debuginfo", rpm:"libecpg6-debuginfo~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpq5-debuginfo", rpm:"libpq5-debuginfo~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql94", rpm:"postgresql94~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql94-contrib", rpm:"postgresql94-contrib~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql94-contrib-debuginfo", rpm:"postgresql94-contrib-debuginfo~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql94-debuginfo", rpm:"postgresql94-debuginfo~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql94-debugsource", rpm:"postgresql94-debugsource~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql94-devel", rpm:"postgresql94-devel~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql94-devel-debuginfo", rpm:"postgresql94-devel-debuginfo~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql94-libs-debugsource", rpm:"postgresql94-libs-debugsource~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql94-plperl", rpm:"postgresql94-plperl~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql94-plperl-debuginfo", rpm:"postgresql94-plperl-debuginfo~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql94-plpython", rpm:"postgresql94-plpython~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql94-plpython-debuginfo", rpm:"postgresql94-plpython-debuginfo~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql94-pltcl", rpm:"postgresql94-pltcl~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql94-pltcl-debuginfo", rpm:"postgresql94-pltcl-debuginfo~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql94-server", rpm:"postgresql94-server~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql94-server-debuginfo", rpm:"postgresql94-server-debuginfo~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql94-test", rpm:"postgresql94-test~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libecpg6-32bit", rpm:"libecpg6-32bit~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libecpg6-debuginfo-32bit", rpm:"libecpg6-debuginfo-32bit~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpq5-debuginfo-32bit", rpm:"libpq5-debuginfo-32bit~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql94-docs", rpm:"postgresql94-docs~9.4.6~4.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
