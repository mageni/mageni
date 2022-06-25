###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2294_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for libcdio openSUSE-SU-2018:2294-1 (libcdio)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851965");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2017-18199", "CVE-2017-18201");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:23:38 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for libcdio openSUSE-SU-2018:2294-1 (libcdio)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-08/msg00040.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcdio'
  package(s) announced via the openSUSE-SU-2018:2294_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libcdio fixes the following issues:

  The following security vulnerabilities were addressed:

  - CVE-2017-18199: Fixed a NULL pointer dereference in realloc_symlink in
  rock.c (bsc#1082821)

  - CVE-2017-18201: Fixed a double free vulnerability in
  get_cdtext_generic() in _cdio_generic.c (bsc#1082877)

  - Fixed several memory leaks (bsc#1082821)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-857=1");

  script_tag(name:"affected", value:"libcdio on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"libcdio++0", rpm:"libcdio++0~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcdio++0-debuginfo", rpm:"libcdio++0-debuginfo~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcdio-debugsource", rpm:"libcdio-debugsource~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcdio-devel", rpm:"libcdio-devel~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcdio16", rpm:"libcdio16~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcdio16-debuginfo", rpm:"libcdio16-debuginfo~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libiso9660-10", rpm:"libiso9660-10~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libiso9660-10-debuginfo", rpm:"libiso9660-10-debuginfo~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudf0", rpm:"libudf0~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudf0-debuginfo", rpm:"libudf0-debuginfo~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cdio-utils", rpm:"cdio-utils~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cdio-utils-debuginfo", rpm:"cdio-utils-debuginfo~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cdio-utils-debugsource", rpm:"cdio-utils-debugsource~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcdio++0-32bit", rpm:"libcdio++0-32bit~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcdio++0-32bit-debuginfo", rpm:"libcdio++0-32bit-debuginfo~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcdio16-32bit", rpm:"libcdio16-32bit~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcdio16-32bit-debuginfo", rpm:"libcdio16-32bit-debuginfo~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libiso9660-10-32bit", rpm:"libiso9660-10-32bit~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libiso9660-10-32bit-debuginfo", rpm:"libiso9660-10-32bit-debuginfo~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudf0-32bit", rpm:"libudf0-32bit~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudf0-32bit-debuginfo", rpm:"libudf0-32bit-debuginfo~0.94~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
