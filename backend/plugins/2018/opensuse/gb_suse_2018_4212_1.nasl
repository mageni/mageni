###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_4212_1.nasl 12882 2018-12-27 07:14:01Z santu $
#
# SuSE Update for keepalived openSUSE-SU-2018:4212-1 (keepalived)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852199");
  script_version("$Revision: 12882 $");
  script_cve_id("CVE-2018-19044", "CVE-2018-19045", "CVE-2018-19046");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-27 08:14:01 +0100 (Thu, 27 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-22 04:00:40 +0100 (Sat, 22 Dec 2018)");
  script_name("SuSE Update for keepalived openSUSE-SU-2018:4212-1 (keepalived)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.3|openSUSELeap15\.0)");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-12/msg00053.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'keepalived'
  package(s) announced via the openSUSE-SU-2018:4212_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for keepalived to version 2.0.10 fixes the following issues:

  Security issues fixed (bsc#1015141):

  - CVE-2018-19044: Fixed a check for pathnames with symlinks when writing
  data to a temporary file upon a call to PrintData or PrintStats

  - CVE-2018-19045: Fixed mode when creating new temporary files upon a call
  to PrintData or PrintStats

  - CVE-2018-19046: Fixed a check for existing plain files when writing data
  to a temporary file upon a call to PrintData or PrintStats

  Non-security issues fixed:

  - Replace references to /var/adm/fillup-templates with new %_fillupdir
  macro (boo#1069468)

  - Use getaddrinfo instead of gethostbyname to workaround glibc
  gethostbyname function buffer overflow (bsc#949238)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1575=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1575=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2018-1575=1");

  script_tag(name:"affected", value:"keepalived on openSUSE Leap 42.3, openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"keepalived", rpm:"keepalived~2.0.10~7.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"keepalived-debuginfo", rpm:"keepalived-debuginfo~2.0.10~7.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"keepalived-debugsource", rpm:"keepalived-debugsource~2.0.10~7.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"keepalived", rpm:"keepalived~2.0.10~lp150.3.4.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"keepalived-debuginfo", rpm:"keepalived-debuginfo~2.0.10~lp150.3.4.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"keepalived-debugsource", rpm:"keepalived-debugsource~2.0.10~lp150.3.4.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
