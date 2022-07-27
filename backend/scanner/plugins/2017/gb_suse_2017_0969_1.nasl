###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_0969_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for apparmor openSUSE-SU-2017:0969-1 (apparmor)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851534");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-04-11 06:34:37 +0200 (Tue, 11 Apr 2017)");
  script_cve_id("CVE-2017-6507");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for apparmor openSUSE-SU-2017:0969-1 (apparmor)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'apparmor'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for apparmor fixes the following issues:

  These security issues were fixed:

  - CVE-2017-6507: Preserve unknown profiles when reloading apparmor.service
  (lp#1668892, boo#1029696)

  - boo#1017260: Migration to apparmor.service accidentally disable AppArmor.
  Note: This will re-enable AppArmor if it was disabled by the last
  update. You'll need to 'rcapparmor reload' to actually load the
  profiles, and then check aa-status for programs that need to be
  restarted to apply the profiles.

  These non-security issues were fixed:

  - Fixed crash in aa-logprof on specific change_hat events

  - boo#1016259: Added var.mount dependency to apparmor.service

  The aa-remove-unknown utility was added to unload unknown profiles
  (lp#1668892)");
  script_tag(name:"affected", value:"apparmor on openSUSE Leap 42.2, openSUSE Leap 42.1");
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

  if ((res = isrpmvuln(pkg:"apache2-mod_apparmor", rpm:"apache2-mod_apparmor~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-mod_apparmor-debuginfo", rpm:"apache2-mod_apparmor-debuginfo~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apparmor-debugsource", rpm:"apparmor-debugsource~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apparmor-parser", rpm:"apparmor-parser~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apparmor-parser-debuginfo", rpm:"apparmor-parser-debuginfo~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libapparmor-devel", rpm:"libapparmor-devel~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libapparmor1", rpm:"libapparmor1~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libapparmor1-debuginfo", rpm:"libapparmor1-debuginfo~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam_apparmor", rpm:"pam_apparmor~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam_apparmor-debuginfo", rpm:"pam_apparmor-debuginfo~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-apparmor", rpm:"perl-apparmor~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-apparmor-debuginfo", rpm:"perl-apparmor-debuginfo~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-apparmor", rpm:"python3-apparmor~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-apparmor-debuginfo", rpm:"python3-apparmor-debuginfo~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-apparmor", rpm:"ruby-apparmor~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-apparmor-debuginfo", rpm:"ruby-apparmor-debuginfo~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libapparmor1-32bit", rpm:"libapparmor1-32bit~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libapparmor1-debuginfo-32bit", rpm:"libapparmor1-debuginfo-32bit~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam_apparmor-32bit", rpm:"pam_apparmor-32bit~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam_apparmor-debuginfo-32bit", rpm:"pam_apparmor-debuginfo-32bit~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apparmor-abstractions", rpm:"apparmor-abstractions~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apparmor-docs", rpm:"apparmor-docs~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apparmor-parser-lang", rpm:"apparmor-parser-lang~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apparmor-profiles", rpm:"apparmor-profiles~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apparmor-utils", rpm:"apparmor-utils~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apparmor-utils-lang", rpm:"apparmor-utils-lang~2.10.2~12.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"apache2-mod_apparmor", rpm:"apache2-mod_apparmor~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-mod_apparmor-debuginfo", rpm:"apache2-mod_apparmor-debuginfo~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apparmor-debugsource", rpm:"apparmor-debugsource~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apparmor-parser", rpm:"apparmor-parser~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apparmor-parser-debuginfo", rpm:"apparmor-parser-debuginfo~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libapparmor-devel", rpm:"libapparmor-devel~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libapparmor1", rpm:"libapparmor1~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libapparmor1-debuginfo", rpm:"libapparmor1-debuginfo~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam_apparmor", rpm:"pam_apparmor~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam_apparmor-debuginfo", rpm:"pam_apparmor-debuginfo~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-apparmor", rpm:"perl-apparmor~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-apparmor-debuginfo", rpm:"perl-apparmor-debuginfo~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-apparmor", rpm:"python3-apparmor~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-apparmor-debuginfo", rpm:"python3-apparmor-debuginfo~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-apparmor", rpm:"ruby-apparmor~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-apparmor-debuginfo", rpm:"ruby-apparmor-debuginfo~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apparmor-abstractions", rpm:"apparmor-abstractions~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apparmor-docs", rpm:"apparmor-docs~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apparmor-parser-lang", rpm:"apparmor-parser-lang~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apparmor-profiles", rpm:"apparmor-profiles~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apparmor-utils", rpm:"apparmor-utils~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apparmor-utils-lang", rpm:"apparmor-utils-lang~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libapparmor1-32bit", rpm:"libapparmor1-32bit~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libapparmor1-debuginfo-32bit", rpm:"libapparmor1-debuginfo-32bit~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam_apparmor-32bit", rpm:"pam_apparmor-32bit~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam_apparmor-debuginfo-32bit", rpm:"pam_apparmor-debuginfo-32bit~2.10.2~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
