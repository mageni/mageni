###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_1272_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for kauth, openSUSE-SU-2017:1272-1 (kauth,)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851554");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-05-16 06:53:20 +0200 (Tue, 16 May 2017)");
  script_cve_id("CVE-2017-8422");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for kauth, openSUSE-SU-2017:1272-1 (kauth, )");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kauth.'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for kauth and kdelibs4 fixes the following issues:

  - CVE-2017-8422: logic flaw in the KAuth framework allowed privilege
  escalation (boo#1036244).");
  script_tag(name:"affected", value:"kauth, on openSUSE Leap 42.2, openSUSE Leap 42.1");
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

  if ((res = isrpmvuln(pkg:"kauth-debugsource", rpm:"kauth-debugsource~5.26.0~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kauth-devel", rpm:"kauth-devel~5.26.0~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4", rpm:"kdelibs4~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4-branding-upstream", rpm:"kdelibs4-branding-upstream~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4-core", rpm:"kdelibs4-core~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4-core-debuginfo", rpm:"kdelibs4-core-debuginfo~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4-debuginfo", rpm:"kdelibs4-debuginfo~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4-debugsource", rpm:"kdelibs4-debugsource~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4-doc", rpm:"kdelibs4-doc~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4-doc-debuginfo", rpm:"kdelibs4-doc-debuginfo~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libKF5Auth5", rpm:"libKF5Auth5~5.26.0~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libKF5Auth5-debuginfo", rpm:"libKF5Auth5-debuginfo~5.26.0~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkde4", rpm:"libkde4~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkde4-debuginfo", rpm:"libkde4-debuginfo~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkde4-devel", rpm:"libkde4-devel~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdecore4", rpm:"libkdecore4~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdecore4-debuginfo", rpm:"libkdecore4-debuginfo~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdecore4-devel", rpm:"libkdecore4-devel~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdecore4-devel-debuginfo", rpm:"libkdecore4-devel-debuginfo~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libksuseinstall-devel", rpm:"libksuseinstall-devel~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libksuseinstall1", rpm:"libksuseinstall1~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libksuseinstall1-debuginfo", rpm:"libksuseinstall1-debuginfo~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kauth-devel-32bit", rpm:"kauth-devel-32bit~5.26.0~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libKF5Auth5-32bit", rpm:"libKF5Auth5-32bit~5.26.0~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libKF5Auth5-debuginfo-32bit", rpm:"libKF5Auth5-debuginfo-32bit~5.26.0~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkde4-32bit", rpm:"libkde4-32bit~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkde4-debuginfo-32bit", rpm:"libkde4-debuginfo-32bit~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdecore4-32bit", rpm:"libkdecore4-32bit~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdecore4-debuginfo-32bit", rpm:"libkdecore4-debuginfo-32bit~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libksuseinstall1-32bit", rpm:"libksuseinstall1-32bit~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libksuseinstall1-debuginfo-32bit", rpm:"libksuseinstall1-debuginfo-32bit~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4-apidocs", rpm:"kdelibs4-apidocs~4.14.25~7.4.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libKF5Auth5-lang", rpm:"libKF5Auth5-lang~5.26.0~2.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"kauth-debugsource", rpm:"kauth-debugsource~5.21.0~16.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kauth-devel", rpm:"kauth-devel~5.21.0~16.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4", rpm:"kdelibs4~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4-branding-upstream", rpm:"kdelibs4-branding-upstream~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4-core", rpm:"kdelibs4-core~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4-core-debuginfo", rpm:"kdelibs4-core-debuginfo~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4-debuginfo", rpm:"kdelibs4-debuginfo~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4-debugsource", rpm:"kdelibs4-debugsource~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4-doc", rpm:"kdelibs4-doc~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4-doc-debuginfo", rpm:"kdelibs4-doc-debuginfo~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libKF5Auth5", rpm:"libKF5Auth5~5.21.0~16.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libKF5Auth5-debuginfo", rpm:"libKF5Auth5-debuginfo~5.21.0~16.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkde4", rpm:"libkde4~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkde4-debuginfo", rpm:"libkde4-debuginfo~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkde4-devel", rpm:"libkde4-devel~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdecore4", rpm:"libkdecore4~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdecore4-debuginfo", rpm:"libkdecore4-debuginfo~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdecore4-devel", rpm:"libkdecore4-devel~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdecore4-devel-debuginfo", rpm:"libkdecore4-devel-debuginfo~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libksuseinstall-devel", rpm:"libksuseinstall-devel~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libksuseinstall1", rpm:"libksuseinstall1~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libksuseinstall1-debuginfo", rpm:"libksuseinstall1-debuginfo~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs4-apidocs", rpm:"kdelibs4-apidocs~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libKF5Auth5-lang", rpm:"libKF5Auth5-lang~5.21.0~16.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kauth-devel-32bit", rpm:"kauth-devel-32bit~5.21.0~16.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libKF5Auth5-32bit", rpm:"libKF5Auth5-32bit~5.21.0~16.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libKF5Auth5-debuginfo-32bit", rpm:"libKF5Auth5-debuginfo-32bit~5.21.0~16.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkde4-32bit", rpm:"libkde4-32bit~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkde4-debuginfo-32bit", rpm:"libkde4-debuginfo-32bit~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdecore4-32bit", rpm:"libkdecore4-32bit~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdecore4-debuginfo-32bit", rpm:"libkdecore4-debuginfo-32bit~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libksuseinstall1-32bit", rpm:"libksuseinstall1-32bit~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libksuseinstall1-debuginfo-32bit", rpm:"libksuseinstall1-debuginfo-32bit~4.14.18~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
