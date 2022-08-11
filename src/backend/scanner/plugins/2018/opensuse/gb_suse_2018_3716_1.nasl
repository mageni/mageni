###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_3716_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for opensc openSUSE-SU-2018:3716-1 (opensc)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852117");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2018-16391", "CVE-2018-16392", "CVE-2018-16393", "CVE-2018-16418",
                "CVE-2018-16419", "CVE-2018-16420", "CVE-2018-16421", "CVE-2018-16422",
                "CVE-2018-16423", "CVE-2018-16424", "CVE-2018-16425", "CVE-2018-16426",
                "CVE-2018-16427");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-10 05:58:37 +0100 (Sat, 10 Nov 2018)");
  script_name("SuSE Update for opensc openSUSE-SU-2018:3716-1 (opensc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-11/msg00016.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensc'
  package(s) announced via the openSUSE-SU-2018:3716_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opensc fixes the following security issues:

  - CVE-2018-16391: Fixed a denial of service when handling responses from a
  Muscle Card (bsc#1106998)

  - CVE-2018-16392: Fixed a denial of service when handling responses from a
  TCOS Card (bsc#1106999)

  - CVE-2018-16393: Fixed buffer overflows when handling responses from
  Gemsafe V1 Smartcards (bsc#1108318)

  - CVE-2018-16418: Fixed buffer overflow when handling string concatenation
  in util_acl_to_str (bsc#1107039)

  - CVE-2018-16419: Fixed several buffer overflows when handling responses
  from a Cryptoflex card (bsc#1107107)

  - CVE-2018-16420: Fixed buffer overflows when handling responses from an
  ePass 2003 Card (bsc#1107097)

  - CVE-2018-16421: Fixed buffer overflows when handling responses from a
  CAC Card (bsc#1107049)

  - CVE-2018-16422: Fixed single byte buffer overflow when handling
  responses from an esteid Card (bsc#1107038)

  - CVE-2018-16423: Fixed double free when handling responses from a
  smartcard (bsc#1107037)

  - CVE-2018-16424: Fixed double free when handling responses in read_file
  (bsc#1107036)

  - CVE-2018-16425: Fixed double free when handling responses from an HSM
  Card (bsc#1107035)

  - CVE-2018-16426: Fixed endless recursion when handling responses from an
  IAS-ECC card (bsc#1107034)

  - CVE-2018-16427: Fixed out of bounds reads when handling responses in
  OpenSC (bsc#1107033)


  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1385=1");

  script_tag(name:"affected", value:"opensc on openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.18.0~lp150.2.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opensc-debuginfo", rpm:"opensc-debuginfo~0.18.0~lp150.2.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opensc-debugsource", rpm:"opensc-debugsource~0.18.0~lp150.2.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opensc-32bit", rpm:"opensc-32bit~0.18.0~lp150.2.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opensc-32bit-debuginfo", rpm:"opensc-32bit-debuginfo~0.18.0~lp150.2.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
