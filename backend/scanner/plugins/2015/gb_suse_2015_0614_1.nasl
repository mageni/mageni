###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0614_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for libXfont openSUSE-SU-2015:0614-1 (libXfont)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850645");
  script_version("$Revision: 12381 $");
  script_cve_id("CVE-2015-1802", "CVE-2015-1803", "CVE-2015-1804");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-03-28 05:29:00 +0100 (Sat, 28 Mar 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for libXfont openSUSE-SU-2015:0614-1 (libXfont)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libXfont'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"libXFont was updated to fix three vulnerabilities when parsing BDF files
  (bnc#921978)

  As libXfont is used by the X server to read font files, and an
  unprivileged user with access to the X server can tell the X server to
  read a given font file from a path of their choosing, these
  vulnerabilities have the potential to allow unprivileged users to run code
  with the privileges of the X server.

  The following vulnerabilities were fixed:

  * The BDF parser could allocate the a wrong buffer size, leading to out of
  bound writes (CVE-2015-1802)

  * The BDF parser could crash when trying to read an invalid pointer
  (CVE-2015-1803)

  * The BDF parser could read 32 bit metrics values into 16 bit integers,
  causing an out-of-bound memory access though integer overflow
  (CVE-2015-1804)");
  script_tag(name:"affected", value:"libXfont on openSUSE 13.1");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.1")
{

  if ((res = isrpmvuln(pkg:"libXfont-debugsource", rpm:"libXfont-debugsource~1.4.6~2.12.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont-devel", rpm:"libXfont-devel~1.4.6~2.12.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont1", rpm:"libXfont1~1.4.6~2.12.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont1-debuginfo", rpm:"libXfont1-debuginfo~1.4.6~2.12.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont-devel-32bit", rpm:"libXfont-devel-32bit~1.4.6~2.12.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont1-32bit", rpm:"libXfont1-32bit~1.4.6~2.12.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont1-debuginfo-32bit", rpm:"libXfont1-debuginfo-32bit~1.4.6~2.12.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
