###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_4299_1.nasl 12963 2019-01-08 07:50:52Z ckuersteiner $
#
# SuSE Update for libraw openSUSE-SU-2018:4299-1 (libraw)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.852220");
  script_version("$Revision: 12963 $");
  script_cve_id("CVE-2018-5804", "CVE-2018-5805", "CVE-2018-5806", "CVE-2018-5808", "CVE-2018-5816");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 08:50:52 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-01 04:01:13 +0100 (Tue, 01 Jan 2019)");
  script_name("SuSE Update for libraw openSUSE-SU-2018:4299-1 (libraw)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-12/msg00072.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libraw'
  package(s) announced via the openSUSE-SU-2018:4299_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libraw fixes the following issues:

  The following security vulnerabilities were addressed:

  - CVE-2018-5804: Fixed a type confusion error within the identify function
  that could trigger a division by zero, leading to a denial of service
  (Dos). (boo#1097975)

  - CVE-2018-5805: Fixed a boundary error within the quicktake_100_load_raw
  function that could cause a stack-based buffer overflow and subsequently
  trigger a crash. (boo#1097973)

  - CVE-2018-5806: Fixed an error within the leaf_hdr_load_raw function that
  could trigger a NULL pointer deference, leading to a denial of service
  (DoS). (boo#1097974)

  - CVE-2018-5808: Fixed an error within the find_green function that could
  cause a stack-based buffer overflow and subsequently execute arbitrary
  code. (boo#1118894)

  - CVE-2018-5816: Fixed a type confusion error within the identify function
  that could trigger a division by zero, leading to a denial of service
  (DoS). (boo#1097975)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1619=1");

  script_tag(name:"affected", value:"libraw on openSUSE Leap 42.3.");

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

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"libraw-debugsource", rpm:"libraw-debugsource~0.17.1~26.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw-devel", rpm:"libraw-devel~0.17.1~26.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw-devel-static", rpm:"libraw-devel-static~0.17.1~26.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw-tools", rpm:"libraw-tools~0.17.1~26.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw-tools-debuginfo", rpm:"libraw-tools-debuginfo~0.17.1~26.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw15", rpm:"libraw15~0.17.1~26.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw15-debuginfo", rpm:"libraw15-debuginfo~0.17.1~26.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
