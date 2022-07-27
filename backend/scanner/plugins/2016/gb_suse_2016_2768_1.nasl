###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_2768_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for curl openSUSE-SU-2016:2768-1 (curl)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851432");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-11 05:47:41 +0100 (Fri, 11 Nov 2016)");
  script_cve_id("CVE-2016-7167", "CVE-2016-8615", "CVE-2016-8616", "CVE-2016-8617",
                "CVE-2016-8618", "CVE-2016-8619", "CVE-2016-8620", "CVE-2016-8621",
                "CVE-2016-8622", "CVE-2016-8623", "CVE-2016-8624");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for curl openSUSE-SU-2016:2768-1 (curl)");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for curl fixes the following security issues:

  - CVE-2016-8624: invalid URL parsing with '#' (bsc#1005646)

  - CVE-2016-8623: Use-after-free via shared cookies (bsc#1005645)

  - CVE-2016-8622: URL unescape heap overflow via integer truncation
  (bsc#1005643)

  - CVE-2016-8621: curl_getdate read out of bounds (bsc#1005642)

  - CVE-2016-8620: glob parser write/read out of bounds (bsc#1005640)

  - CVE-2016-8619: double-free in krb5 code (bsc#1005638)

  - CVE-2016-8618: double-free in curl_maprintf (bsc#1005637)

  - CVE-2016-8617: OOB write via unchecked multiplication (bsc#1005635)

  - CVE-2016-8616: case insensitive password comparison (bsc#1005634)

  - CVE-2016-8615: cookie injection for other servers (bsc#1005633)

  - CVE-2016-7167: escape and unescape integer overflows (bsc#998760)

  This update was imported from the SUSE:SLE-12:Update update project.");
  script_tag(name:"affected", value:"curl on openSUSE Leap 42.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl'
  package(s) announced via the referenced advisory.");
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

  if ((res = isrpmvuln(pkg:"curl", rpm:"curl~7.37.0~16.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"curl-debuginfo", rpm:"curl-debuginfo~7.37.0~16.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"curl-debugsource", rpm:"curl-debugsource~7.37.0~16.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.37.0~16.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.37.0~16.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl4-debuginfo", rpm:"libcurl4-debuginfo~7.37.0~16.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl-devel-32bit", rpm:"libcurl-devel-32bit~7.37.0~16.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl4-32bit", rpm:"libcurl4-32bit~7.37.0~16.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl4-debuginfo-32bit", rpm:"libcurl4-debuginfo-32bit~7.37.0~16.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
