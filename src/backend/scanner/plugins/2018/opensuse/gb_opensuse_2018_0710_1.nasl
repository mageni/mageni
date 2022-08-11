###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0710_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for ucode-intel openSUSE-SU-2018:0710-1 (ucode-intel)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851716");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-03-17 08:44:41 +0100 (Sat, 17 Mar 2018)");
  script_cve_id("CVE-2017-5715");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for ucode-intel openSUSE-SU-2018:0710-1 (ucode-intel)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

  The Intel CPU microcode version was updated to version 20180312.

  This update enables the IBPB+IBRS based mitigations of the Spectre v2
  flaws (boo#1085207 CVE-2017-5715)

  - New Platforms

  - BDX-DE EGW A0 6-56-5:10 e000009

  - SKX B1 6-55-3:97 1000140

  - Updates

  - SNB D2 6-2a-7:12 29- 2d

  - JKT C1 6-2d-6:6d 619- 61c

  - JKT C2 6-2d-7:6d 710- 713

  - IVB E2 6-3a-9:12 1c- 1f

  - IVT C0 6-3e-4:ed 428- 42c

  - IVT D1 6-3e-7:ed 70d- 713

  - HSW Cx/Dx 6-3c-3:32 22- 24

  - HSW-ULT Cx/Dx 6-45-1:72 20- 23

  - CRW Cx 6-46-1:32 17- 19

  - HSX C0 6-3f-2:6f 3a- 3c

  - HSX-EX E0 6-3f-4:80 0f- 11

  - BDW-U/Y E/F 6-3d-4:c0 25- 2a

  - BDW-H E/G 6-47-1:22 17- 1d

  - BDX-DE V0/V1 6-56-2:10 0f- 15

  - BDW-DE V2 6-56-3:10 700000d- 7000012

  - BDW-DE Y0 6-56-4:10 f00000a- f000011

  - SKL-U/Y D0 6-4e-3:c0 ba- c2

  - SKL R0 6-5e-3:36 ba- c2

  - KBL-U/Y H0 6-8e-9:c0 62- 84

  - KBL B0 6-9e-9:2a 5e- 84

  - CFL D0 6-8e-a:c0 70- 84

  - CFL U0 6-9e-a:22 70- 84

  - CFL B0 6-9e-b:02 72- 84

  - SKX H0 6-55-4:b7 2000035- 2000043");
  script_tag(name:"affected", value:"ucode-intel on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-03/msg00045.html");
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

  if ((res = isrpmvuln(pkg:"ucode-intel-20180312", rpm:"ucode-intel-20180312~22.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ucode-intel-blob-20180312", rpm:"ucode-intel-blob-20180312~22.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ucode-intel-debuginfo-20180312", rpm:"ucode-intel-debuginfo-20180312~22.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ucode-intel-debugsource-20180312", rpm:"ucode-intel-debugsource-20180312~22.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
