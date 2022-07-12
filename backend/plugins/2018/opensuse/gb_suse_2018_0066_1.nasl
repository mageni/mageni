###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0066_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for ucode-intel openSUSE-SU-2018:0066-1 (ucode-intel)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851681");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-01-12 07:44:31 +0100 (Fri, 12 Jan 2018)");
  script_cve_id("CVE-2017-5715");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for ucode-intel openSUSE-SU-2018:0066-1 (ucode-intel)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for ucode-intel fixes
  the following issues:

  Update to Intel CPU Microcode version 20180108 (boo#1075262)

  - The pre-released microcode fixing some important security issues is now
  officially published (and included in the added tarball).

  New firmware updates since last version (20170707) are available for these
  Intel processors:

  - IVT C0          (06-3e-04:ed) 428- 42a

  - SKL-U/Y D0      (06-4e-03:c0) ba- c2

  - BDW-U/Y E/F     (06-3d-04:c0) 25- 28

  - HSW-ULT Cx/Dx   (06-45-01:72) 20- 21

  - Crystalwell Cx  (06-46-01:32) 17- 18

  - BDW-H E/G       (06-47-01:22) 17- 1b

  - HSX-EX E0       (06-3f-04:80) 0f- 10

  - SKL-H/S R0      (06-5e-03:36) ba- c2

  - HSW Cx/Dx       (06-3c-03:32) 22- 23

  - HSX C0          (06-3f-02:6f) 3a- 3b

  - BDX-DE V0/V1    (06-56-02:10) 0f- 14

  - BDX-DE V2       (06-56-03:10) 700000d- 7000011

  - KBL-U/Y H0      (06-8e-09:c0) 62- 80

  - KBL Y0 / CFL D0 (06-8e-0a:c0) 70- 80

  - KBL-H/S B0      (06-9e-09:2a) 5e- 80

  - CFL U0          (06-9e-0a:22) 70- 80

  - CFL B0          (06-9e-0b:02) 72- 80

  - SKX H0          (06-55-04:b7) 2000035- 200003c

  - GLK B0          (06-7a-01:01) 1e- 22");
  script_tag(name:"affected", value:"ucode-intel on openSUSE Leap 42.3, openSUSE Leap 42.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-01/msg00031.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.3)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"ucode-intel-20180108", rpm:"ucode-intel-20180108~7.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ucode-intel-blob-20180108", rpm:"ucode-intel-blob-20180108~7.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ucode-intel-debuginfo-20180108", rpm:"ucode-intel-debuginfo-20180108~7.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ucode-intel-debugsource-20180108", rpm:"ucode-intel-debugsource-20180108~7.12.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"ucode-intel-20180108", rpm:"ucode-intel-20180108~16.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ucode-intel-blob-20180108", rpm:"ucode-intel-blob-20180108~16.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ucode-intel-debuginfo-20180108", rpm:"ucode-intel-debuginfo-20180108~16.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ucode-intel-debugsource-20180108", rpm:"ucode-intel-debugsource-20180108~16.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
