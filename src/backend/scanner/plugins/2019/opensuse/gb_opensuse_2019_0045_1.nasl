###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2019_0045_1.nasl 13489 2019-02-06 09:12:08Z cfischer $
#
# SuSE Update for LibVNCServer openSUSE-SU-2019:0045-1 (LibVNCServer)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852230");
  script_version("$Revision: 13489 $");
  script_cve_id("CVE-2018-15126", "CVE-2018-15127", "CVE-2018-20019", "CVE-2018-20020",
                "CVE-2018-20021", "CVE-2018-20022", "CVE-2018-20023", "CVE-2018-20024",
                "CVE-2018-6307");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 10:12:08 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-12 04:01:32 +0100 (Sat, 12 Jan 2019)");
  script_name("SuSE Update for LibVNCServer openSUSE-SU-2019:0045-1 (LibVNCServer)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-01/msg00011.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'LibVNCServer'
  package(s) announced via the openSUSE-SU-2019:0045_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for LibVNCServer fixes the following issues:

  Security issues fixed:

  - CVE-2018-15126: Fixed use-after-free in file transfer extension
  (bsc#1120114)

  - CVE-2018-6307: Fixed use-after-free in file transfer extension server
  code (bsc#1120115)

  - CVE-2018-20020: Fixed heap out-of-bound write inside structure in VNC
  client code (bsc#1120116)

  - CVE-2018-15127: Fixed heap out-of-bounds write in rfbserver.c
  (bsc#1120117)

  - CVE-2018-20019: Fixed multiple heap out-of-bound writes in VNC client
  code (bsc#1120118)

  - CVE-2018-20023: Fixed information disclosure through improper
  initialization in VNC Repeater client code (bsc#1120119)

  - CVE-2018-20022: Fixed information disclosure through improper
  initialization in VNC client code (bsc#1120120)

  - CVE-2018-20024: Fixed NULL pointer dereference in VNC client code
  (bsc#1120121)

  - CVE-2018-20021: Fixed infinite loop in VNC client code (bsc#1120122)

  This update was imported from the SUSE:SLE-12:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-45=1");

  script_tag(name:"affected", value:"LibVNCServer on openSUSE Leap 42.3.");

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

  if ((res = isrpmvuln(pkg:"LibVNCServer-debugsource", rpm:"LibVNCServer-debugsource~0.9.9~16.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"LibVNCServer-devel", rpm:"LibVNCServer-devel~0.9.9~16.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvncclient0", rpm:"libvncclient0~0.9.9~16.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvncclient0-debuginfo", rpm:"libvncclient0-debuginfo~0.9.9~16.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvncserver0", rpm:"libvncserver0~0.9.9~16.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvncserver0-debuginfo", rpm:"libvncserver0-debuginfo~0.9.9~16.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"linuxvnc", rpm:"linuxvnc~0.9.9~16.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"linuxvnc-debuginfo", rpm:"linuxvnc-debuginfo~0.9.9~16.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
