# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.853726");
  script_version("2021-04-21T07:29:02+0000");
  script_cve_id("CVE-2011-4953", "CVE-2012-2395", "CVE-2017-1000469", "CVE-2018-1000225", "CVE-2018-1000226", "CVE-2018-10931");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 05:01:45 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for cobbler (openSUSE-SU-2021:0046-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0046-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KL7UG4FHNZKUU44UQUG34HXRAOJ27FI2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cobbler'
  package(s) announced via the openSUSE-SU-2021:0046-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cobbler fixes the following issues:

  - Add cobbler-tests subpackage for unit testing for openSUSE/SLE

  - Adds LoadModule definitions for openSUSE/SLE

  - Switch to new refactored auth module.

  - use systemctl to restart cobblerd on logfile rotation (boo#1169207)
       Mainline logrotate conf file uses already /sbin/service instead of
       outdated: /etc/init.d/cobblerd

  - Fix cobbler sync for DHCP or DNS (boo#1169553) Fixed mainline by commit
       2d6cfe42da

  - Signatures file now uses 'default_autoinstall' which fixes import
       problem happening with some distributions (boo#1159010)

  - Fix for kernel and initrd detection (boo#1159010)

  - New:

  * For the distro there is now a parameter remote_boot_initrd and
         remote_boot_kernel ()

  * For the profile there is now a parameter filename for DHCP. (#2280)

  * Signatures for ESXi 6 and 7 (#2308)

  * The hardlink command is now detected more dynamically and thus more
         error resistant (#2297)

  * HTTPBoot will now work in some cases out of the bug. (#2295)

  * Additional DNS query for a case where the wrong record was queried in
         the nsupdate system case (#2285)

  - Changes:

  * Enabled a lot of tests, removed some and implemented new. (#2202)

  * Removed not used files from the codebase. (#2302)

  * Exchanged mkisofs to xorrisofs. (#2296)

  * Removed duplicate code. (#2224)

  * Removed unreachable code. (#2223)

  * Snippet creation and deletion now works again via xmlrpc. (#2244)

  * Replace createrepo with createrepo_c. (#2266)

  * Enable Kerberos through having a case sensitive users.conf. (#2272)

  - Bugfixes:

  * General various Bugfixes (#2331, )

  * Makefile usage and commands. (#2344, #2304)

  * Fix the dhcp template. (#2314)

  * Creation of the management classes and gPXE. (#2310)

  * Fix the scm_track module. (#2275, #2279)

  * Fix passing the netdevice parameter correctly to the linuxrc. (#2263)

  * powerstatus from cobbler now works thanks to a wrapper for ipmitool.
         (#2267)

  * In case the LDAP is used for auth, it now works with ADs. (#2274)

  * Fix passthru authentication. (#2271)

  - Other:

  * Add Codecov. (#2229)

  * Documentation updates. (#2333, #2326, #2305, #2249, #2268)

  * Buildprocess:

  * Recreation and cleanup of Grub2. (#2278)

  * Fix small errors for openSUSE Leap. (#2233)

  * Fix rpmlint errors. (#2237)

  * Maximum compatibility for debbuild package cr ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'cobbler' package(s) on openSUSE Leap 15.2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"cobbler", rpm:"cobbler~3.1.2~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cobbler-tests", rpm:"cobbler-tests~3.1.2~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cobbler-web", rpm:"cobbler-web~3.1.2~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);