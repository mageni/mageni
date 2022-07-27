###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_3035_1.nasl 12496 2018-11-23 03:21:34Z ckuersteiner $
#
# SuSE Update for gitolite openSUSE-SU-2018:3035-1 (gitolite)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851925");
  script_version("$Revision: 12496 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 04:21:34 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-06 08:17:09 +0200 (Sat, 06 Oct 2018)");
  script_cve_id("CVE-2018-16976");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for gitolite openSUSE-SU-2018:3035-1 (gitolite)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'gitolite'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for gitolite fixes the following issues:

  Gitolite was updated to 3.6.9:

  - CVE-2018-16976: prevent racy access to repos in process of migration to
  gitolite (boo#1108272)

  - 'info' learns new '-p' option to show only physical repos (as opposed to
  wild repos)

  The update to 3.6.8 contains:

  - fix bug when deleting *all* hooks for a repo

  - allow trailing slashes in repo names

  - make pre-receive hook driver bail on non-zero exit of a pre-receive hook

  - allow templates in gitolite.conf (new feature)

  - various optimiations

  The update to 3.6.7 contains:

  - allow repo-specific hooks to be organised into subdirectories, and allow
  the multi-hook driver to be placed in some other location of your choice

  - allow simple test code to be embedded within the gitolite.conf file  see
  contrib/utils/testconf for how. (This goes on the client side, not on
  the server)

  - allow syslog 'facility' to be changed, from the default of 'local0'

  - allow syslog 'facility' to be changed, from the default of replaced with
  a space separated list of members

  The update to 3.6.6 contains:

  - simple but important fix for a future perl deprecation (perl will be
  removing '.' from @INC in 5.24)

  - 'perms' now requires a '-c' to activate batch mode (should not affect
  interactive use but check your scripts perhaps?)

  - gitolite setup now accepts a '-m' option to supply a custom message
  (useful when it is used by a script)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1118=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1118=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2018-1118=1");
  script_tag(name:"affected", value:"gitolite on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-10/msg00010.html");
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

  if ((res = isrpmvuln(pkg:"gitolite", rpm:"gitolite~3.6.9~4.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
