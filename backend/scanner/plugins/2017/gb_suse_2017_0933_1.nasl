###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_0933_1.nasl 14110 2019-03-12 09:28:23Z cfischer $
#
# SuSE Update for ruby2.2, openSUSE-SU-2017:0933-1 (ruby2.2,)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851531");
  script_version("$Revision: 14110 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 10:28:23 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-04-06 06:33:15 +0200 (Thu, 06 Apr 2017)");
  script_cve_id("CVE-2015-7551", "CVE-2016-2339");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for ruby2.2, openSUSE-SU-2017:0933-1 (ruby2.2, )");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby2.2.'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for ruby2.2, ruby2.3 fixes the following issues:

  Security issues fixed:

  - CVE-2016-2339: heap overflow vulnerability in the
  Fiddle::Function.new'initialize' (boo#1018808)

  - CVE-2015-7551: Unsafe tainted string usage in Fiddle and DL (boo#959495)

  Detailed ChangeLog are linked in the references.");

  script_xref(name:"URL", value:"http://svn.ruby-lang.org/repos/ruby/tags/v2_2_6/ChangeLog");
  script_xref(name:"URL", value:"http://svn.ruby-lang.org/repos/ruby/tags/v2_3_3/ChangeLog");

  script_tag(name:"affected", value:"ruby2.2, on openSUSE Leap 42.2, openSUSE Leap 42.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.1)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"libruby2_2-2_2", rpm:"libruby2_2-2_2~2.2.6~6.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libruby2_2-2_2-debuginfo", rpm:"libruby2_2-2_2-debuginfo~2.2.6~6.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libruby2_3-2_3", rpm:"libruby2_3-2_3~2.3.3~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libruby2_3-2_3-debuginfo", rpm:"libruby2_3-2_3-debuginfo~2.3.3~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2", rpm:"ruby2.2~2.2.6~6.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-debuginfo", rpm:"ruby2.2-debuginfo~2.2.6~6.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-debugsource", rpm:"ruby2.2-debugsource~2.2.6~6.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-devel", rpm:"ruby2.2-devel~2.2.6~6.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-devel-extra", rpm:"ruby2.2-devel-extra~2.2.6~6.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-doc", rpm:"ruby2.2-doc~2.2.6~6.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-stdlib", rpm:"ruby2.2-stdlib~2.2.6~6.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-stdlib-debuginfo", rpm:"ruby2.2-stdlib-debuginfo~2.2.6~6.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-tk", rpm:"ruby2.2-tk~2.2.6~6.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-tk-debuginfo", rpm:"ruby2.2-tk-debuginfo~2.2.6~6.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.3", rpm:"ruby2.3~2.3.3~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.3-debuginfo", rpm:"ruby2.3-debuginfo~2.3.3~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.3-debugsource", rpm:"ruby2.3-debugsource~2.3.3~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.3-devel", rpm:"ruby2.3-devel~2.3.3~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.3-devel-extra", rpm:"ruby2.3-devel-extra~2.3.3~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.3-doc", rpm:"ruby2.3-doc~2.3.3~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.3-stdlib", rpm:"ruby2.3-stdlib~2.3.3~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.3-stdlib-debuginfo", rpm:"ruby2.3-stdlib-debuginfo~2.3.3~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.3-tk", rpm:"ruby2.3-tk~2.3.3~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.3-tk-debuginfo", rpm:"ruby2.3-tk-debuginfo~2.3.3~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-doc-ri", rpm:"ruby2.2-doc-ri~2.2.6~6.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.3-doc-ri", rpm:"ruby2.3-doc-ri~2.3.3~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"libruby2_2-2_2", rpm:"libruby2_2-2_2~2.2.6~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libruby2_2-2_2-debuginfo", rpm:"libruby2_2-2_2-debuginfo~2.2.6~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2", rpm:"ruby2.2~2.2.6~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-debuginfo", rpm:"ruby2.2-debuginfo~2.2.6~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-debugsource", rpm:"ruby2.2-debugsource~2.2.6~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-devel", rpm:"ruby2.2-devel~2.2.6~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-devel-extra", rpm:"ruby2.2-devel-extra~2.2.6~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-doc", rpm:"ruby2.2-doc~2.2.6~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-stdlib", rpm:"ruby2.2-stdlib~2.2.6~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-stdlib-debuginfo", rpm:"ruby2.2-stdlib-debuginfo~2.2.6~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-tk", rpm:"ruby2.2-tk~2.2.6~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.2-tk-debuginfo", rpm:"ruby2.2-tk-debuginfo~2.2.6~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"uby2.2-doc-ri", rpm:"uby2.2-doc-ri~2.2.6~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
