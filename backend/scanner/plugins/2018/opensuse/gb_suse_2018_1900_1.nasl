###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1900_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for postgresql95 openSUSE-SU-2018:1900-1 (postgresql95)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851808");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-07-06 05:50:39 +0200 (Fri, 06 Jul 2018)");
  script_cve_id("CVE-2018-1115");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for postgresql95 openSUSE-SU-2018:1900-1 (postgresql95)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql95'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"This update for postgresql95 fixes the following issues:

  - Update to PostgreSQL 9.5.13.

  A dump/restore is not required for those running 9.5.X. However, if the
  function marking mistakes mentioned belowpg_logfile_rotate affect you,
  you will want to take steps to correct your database catalogs.

  The functions query_to_xml, cursor_to_xml, cursor_to_xmlschema,
  query_to_xmlschema, and query_to_xml_and_xmlschema should be marked
  volatile because they execute user-supplied queries that might contain
  volatile operations. They were not, leading to a risk of incorrect query
  optimization. This has been repaired for new installations by correcting
  the initial catalog data, but existing installations will continue to
  contain the incorrect markings. Practical use of these functions seems to
  pose little hazard, but in case of trouble, it can be fixed by manually
  updating these functions' pg_proc entries, for example: ALTER FUNCTION
  pg_catalog.query_to_xml(text, boolean, boolean, text) VOLATILE. (Note that
  that will need to be done in each database of the installation.) Another
  option is to pg_upgrade the database to a version containing the corrected
  initial data.

  Security issue fixed:

  - CVE-2018-1115: Remove public execute privilege from contrib/adminpack's
  pg_logfile_rotate() function pg_logfile_rotate() is a deprecated wrapper
  for the core function pg_rotate_logfile(). When that function was
  changed to rely on SQL privileges for access control rather than a
  hard-coded superuser check, pg_logfile_rotate() should have been updated
  as well, but the need for this was missed. Hence, if adminpack is
  installed, any user could request a logfile rotation, creating a minor
  security issue. After installing this update, administrators should
  update adminpack by performing ALTER EXTENSION adminpack UPDATE in each
  database in which adminpack is installed. (bsc#1091610)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-696=1");
  script_tag(name:"affected", value:"postgresql95 on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-07/msg00004.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/9.5/static/release-9-5-13.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"postgresql95", rpm:"postgresql95~9.5.13~2.9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql95-contrib", rpm:"postgresql95-contrib~9.5.13~2.9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql95-contrib-debuginfo", rpm:"postgresql95-contrib-debuginfo~9.5.13~2.9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql95-debuginfo", rpm:"postgresql95-debuginfo~9.5.13~2.9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql95-debugsource", rpm:"postgresql95-debugsource~9.5.13~2.9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql95-devel", rpm:"postgresql95-devel~9.5.13~2.9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql95-devel-debuginfo", rpm:"postgresql95-devel-debuginfo~9.5.13~2.9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql95-libs-debugsource", rpm:"postgresql95-libs-debugsource~9.5.13~2.9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql95-plperl", rpm:"postgresql95-plperl~9.5.13~2.9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql95-plperl-debuginfo", rpm:"postgresql95-plperl-debuginfo~9.5.13~2.9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql95-plpython", rpm:"postgresql95-plpython~9.5.13~2.9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql95-plpython-debuginfo", rpm:"postgresql95-plpython-debuginfo~9.5.13~2.9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql95-pltcl", rpm:"postgresql95-pltcl~9.5.13~2.9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql95-pltcl-debuginfo", rpm:"postgresql95-pltcl-debuginfo~9.5.13~2.9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql95-server", rpm:"postgresql95-server~9.5.13~2.9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql95-server-debuginfo", rpm:"postgresql95-server-debuginfo~9.5.13~2.9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql95-test", rpm:"postgresql95-test~9.5.13~2.9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql95-docs", rpm:"postgresql95-docs~9.5.13~2.9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
