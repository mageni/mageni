###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1955_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for slurm openSUSE-SU-2018:1955-1 (slurm)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852068");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2018-10995");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:41:08 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for slurm openSUSE-SU-2018:1955-1 (slurm)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-07/msg00016.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slurm'
  package(s) announced via the openSUSE-SU-2018:1955_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for slurm to version 17.11.7 fixes the following issues:

  This security issue was fixed:

  - CVE-2018-10995: Ensure correct handling of user names and group ids
  (bsc#1095508).

  These non-security issues were fixed:

  - CRAY - Add slurmsmwd to the contribs/cray dir

  - PMIX - Added the direct connect authentication.

  - Prevent the backup slurmctld from losing the active/available node
  features list on takeover.

  - Be able to force power_down of cloud node even if in power_save state.

  - Allow cloud nodes to be recognized in Slurm when booted out of band.

  - Notify srun and ctld when unkillable stepd exits.

  - Fixes daemoniziation in newly introduced slurmsmwd daemon.

  The following tracked packaging changes are included:

  - avoid  postun error in libpmi0 (bsc#1100850)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-729=1");

  script_tag(name:"affected", value:"slurm on openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"libpmi0", rpm:"libpmi0~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpmi0-debuginfo", rpm:"libpmi0-debuginfo~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libslurm32", rpm:"libslurm32~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libslurm32-debuginfo", rpm:"libslurm32-debuginfo~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-slurm", rpm:"perl-slurm~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-slurm-debuginfo", rpm:"perl-slurm-debuginfo~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm", rpm:"slurm~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-auth-none", rpm:"slurm-auth-none~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-auth-none-debuginfo", rpm:"slurm-auth-none-debuginfo~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-config", rpm:"slurm-config~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-debuginfo", rpm:"slurm-debuginfo~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-debugsource", rpm:"slurm-debugsource~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-devel", rpm:"slurm-devel~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-doc", rpm:"slurm-doc~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-lua", rpm:"slurm-lua~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-lua-debuginfo", rpm:"slurm-lua-debuginfo~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-munge", rpm:"slurm-munge~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-munge-debuginfo", rpm:"slurm-munge-debuginfo~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-node", rpm:"slurm-node~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-node-debuginfo", rpm:"slurm-node-debuginfo~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-openlava", rpm:"slurm-openlava~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-pam_slurm", rpm:"slurm-pam_slurm~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-pam_slurm-debuginfo", rpm:"slurm-pam_slurm-debuginfo~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-plugins", rpm:"slurm-plugins~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-plugins-debuginfo", rpm:"slurm-plugins-debuginfo~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-seff", rpm:"slurm-seff~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-sjstat", rpm:"slurm-sjstat~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-slurmdbd", rpm:"slurm-slurmdbd~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-slurmdbd-debuginfo", rpm:"slurm-slurmdbd-debuginfo~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-sql", rpm:"slurm-sql~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-sql-debuginfo", rpm:"slurm-sql-debuginfo~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-sview", rpm:"slurm-sview~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-sview-debuginfo", rpm:"slurm-sview-debuginfo~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-torque", rpm:"slurm-torque~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slurm-torque-debuginfo", rpm:"slurm-torque-debuginfo~17.11.7~lp150.5.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
