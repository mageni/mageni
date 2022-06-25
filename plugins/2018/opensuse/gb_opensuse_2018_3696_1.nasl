###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for ntfs-3g_ntfsprogs openSUSE-SU-2018:3696-1 (ntfs-3g_ntfsprogs)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852111");
  script_version("2019-05-24T11:20:30+0000");
  script_cve_id("CVE-2017-0358");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2018-11-10 05:57:36 +0100 (Sat, 10 Nov 2018)");
  script_name("SuSE Update for ntfs-3g_ntfsprogs openSUSE-SU-2018:3696-1 (ntfs-3g_ntfsprogs)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-11/msg00008.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntfs-3g_ntfsprogs'
  package(s) announced via the openSUSE-SU-2018:3696_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ntfs-3g_ntfsprogs fixes the following issues:

  - CVE-2017-0358: Missing sanitization of the environment during a call to
  modprobe allowed local users to escalate for root privilege (bsc#1022500)

  This update was imported from the SUSE:SLE-12:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1376=1");

  script_tag(name:"affected", value:"ntfs-3g_ntfsprogs on openSUSE Leap 42.3.");

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

  if ((res = isrpmvuln(pkg:"libntfs-3g-devel", rpm:"libntfs-3g-devel~2013.1.13~7.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libntfs-3g84", rpm:"libntfs-3g84~2013.1.13~7.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libntfs-3g84-debuginfo", rpm:"libntfs-3g84-debuginfo~2013.1.13~7.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntfs-3g", rpm:"ntfs-3g~2013.1.13~7.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntfs-3g-debuginfo", rpm:"ntfs-3g-debuginfo~2013.1.13~7.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntfs-3g_ntfsprogs-debugsource", rpm:"ntfs-3g_ntfsprogs-debugsource~2013.1.13~7.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntfsprogs", rpm:"ntfsprogs~2013.1.13~7.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntfsprogs-debuginfo", rpm:"ntfsprogs-debuginfo~2013.1.13~7.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
