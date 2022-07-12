###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_1642_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for Server openSUSE-SU-2014:1642-1 (Server)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850625");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-12-16 05:58:20 +0100 (Tue, 16 Dec 2014)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for Server openSUSE-SU-2014:1642-1 (Server)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Server'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Firebird server crashes when handling a malformed network packet.");
  script_tag(name:"affected", value:"Server on openSUSE 13.1, openSUSE 12.3");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE12\.3|openSUSE13\.1)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE12.3")
{

  if ((res = isrpmvuln(pkg:"firebird", rpm:"firebird~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-classic", rpm:"firebird-classic~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-classic-debuginfo", rpm:"firebird-classic-debuginfo~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-classic-debugsource", rpm:"firebird-classic-debugsource~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-debuginfo", rpm:"firebird-debuginfo~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-debugsource", rpm:"firebird-debugsource~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-devel", rpm:"firebird-devel~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-superserver", rpm:"firebird-superserver~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-superserver-debuginfo", rpm:"firebird-superserver-debuginfo~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2", rpm:"libfbclient2~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2-debuginfo", rpm:"libfbclient2-debuginfo~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2-devel", rpm:"libfbclient2-devel~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbembed-devel", rpm:"libfbembed-devel~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbembed2_5", rpm:"libfbembed2_5~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbembed2_5-debuginfo", rpm:"libfbembed2_5-debuginfo~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-32bit", rpm:"firebird-32bit~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-debuginfo-32bit", rpm:"firebird-debuginfo-32bit~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2-32bit", rpm:"libfbclient2-32bit~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2-debuginfo-32bit", rpm:"libfbclient2-debuginfo-32bit~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-doc", rpm:"firebird-doc~2.5.2.26539~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSE13.1")
{

  if ((res = isrpmvuln(pkg:"firebird", rpm:"firebird~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-classic", rpm:"firebird-classic~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-classic-debuginfo", rpm:"firebird-classic-debuginfo~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-classic-debugsource", rpm:"firebird-classic-debugsource~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-debuginfo", rpm:"firebird-debuginfo~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-debugsource", rpm:"firebird-debugsource~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-devel", rpm:"firebird-devel~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-superserver", rpm:"firebird-superserver~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-superserver-debuginfo", rpm:"firebird-superserver-debuginfo~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2", rpm:"libfbclient2~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2-debuginfo", rpm:"libfbclient2-debuginfo~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2-devel", rpm:"libfbclient2-devel~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbembed-devel", rpm:"libfbembed-devel~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbembed2_5", rpm:"libfbembed2_5~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbembed2_5-debuginfo", rpm:"libfbembed2_5-debuginfo~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-32bit", rpm:"firebird-32bit~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-debuginfo-32bit", rpm:"firebird-debuginfo-32bit~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2-32bit", rpm:"libfbclient2-32bit~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2-debuginfo-32bit", rpm:"libfbclient2-debuginfo-32bit~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-doc", rpm:"firebird-doc~2.5.2.26539~8.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
