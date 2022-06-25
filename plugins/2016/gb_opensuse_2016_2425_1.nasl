###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_2425_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for postgresql93 openSUSE-SU-2016:2425-1 (postgresql93)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851400");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-05 15:43:12 +0530 (Wed, 05 Oct 2016)");
  script_cve_id("CVE-2016-5423", "CVE-2016-5424");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for postgresql93 openSUSE-SU-2016:2425-1 (postgresql93)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql93'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The postgresql server postgresql93 was updated to 9.3.14 fixes the
  following issues:

  Update to version 9.3.14:

  * Fix possible mis-evaluation of nested CASE-WHEN expressions
  (CVE-2016-5423, boo#993454)

  * Fix client programs' handling of special characters in database and role
  names (CVE-2016-5424, boo#993453)

  * Fix corner-case misbehaviors for IS NULL/IS NOT NULL applied to nested
  composite values

  * Make the inet and cidr data types properly reject IPv6 addresses with
  too many colon-separated fields

  * Prevent crash in close_ps() (the point ## lseg operator) for NaN input
  coordinates

  * Fix several one-byte buffer over-reads in to_number()

  * Avoid unsafe intermediate state during expensive paths through
  heap_update()
  Update to version 9.3.13:

  This update fixes several problems which caused downtime for users,
  including:

  - Clearing the OpenSSL error queue before OpenSSL calls, preventing errors
  in SSL connections, particularly when using the Python, Ruby or PHP
  OpenSSL wrappers

  - Fixed the 'failed to build N-way joins' planner error

  - Fixed incorrect handling of equivalence in multilevel nestloop query
  plans, which could emit rows which didn't match the WHERE clause.

  - Prevented two memory leaks with using GIN indexes, including a potential
  index corruption risk. The release also includes many other bug fixes
  for reported issues, many of which affect all supported versions:

  - Fix corner-case parser failures occurring when
  operator_precedence_warning is turned on

  - Prevent possible misbehavior of TH, th, and Y, YYY format codes in
  to_timestamp()

  - Correct dumping of VIEWs and RULEs which use ANY (array) in a subselect

  - Disallow newlines in ALTER SYSTEM parameter values

  - Avoid possible misbehavior after failing to remove a tablespace symlink

  - Fix crash in logical decoding on alignment-picky platforms

  - Avoid repeated requests for feedback from receiver while shutting down
  walsender

  - Multiple fixes for pg_upgrade

  - Support building with Visual Studio 2015

  - This update also contains tzdata release 2016d, with updates for Russia,
  Venezuela, Kirov, and Tomsk.
  Update to version 9.3.12:

  - Fix two bugs in indexed ROW() comparisons

  - Avoid dat ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"postgresql93 on openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libecpg6-debuginfo", rpm:"libecpg6-debuginfo~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpq5-debuginfo", rpm:"libpq5-debuginfo~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93", rpm:"postgresql93~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-contrib", rpm:"postgresql93-contrib~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-contrib-debuginfo", rpm:"postgresql93-contrib-debuginfo~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-debuginfo", rpm:"postgresql93-debuginfo~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-debugsource", rpm:"postgresql93-debugsource~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-devel", rpm:"postgresql93-devel~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-devel-debuginfo", rpm:"postgresql93-devel-debuginfo~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-libs-debugsource", rpm:"postgresql93-libs-debugsource~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-plperl", rpm:"postgresql93-plperl~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-plperl-debuginfo", rpm:"postgresql93-plperl-debuginfo~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-plpython", rpm:"postgresql93-plpython~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-plpython-debuginfo", rpm:"postgresql93-plpython-debuginfo~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-pltcl", rpm:"postgresql93-pltcl~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-pltcl-debuginfo", rpm:"postgresql93-pltcl-debuginfo~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-server", rpm:"postgresql93-server~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-server-debuginfo", rpm:"postgresql93-server-debuginfo~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-test", rpm:"postgresql93-test~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql93-docs", rpm:"postgresql93-docs~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libecpg6-32bit", rpm:"libecpg6-32bit~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libecpg6-debuginfo-32bit", rpm:"libecpg6-debuginfo-32bit~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpq5-debuginfo-32bit", rpm:"libpq5-debuginfo-32bit~9.3.14~2.13.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
