# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852797");
  script_version("2019-12-06T11:38:15+0000");
  script_cve_id("CVE-2019-13178");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-12-06 11:38:15 +0000 (Fri, 06 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-04 03:02:35 +0000 (Wed, 04 Dec 2019)");
  script_name("openSUSE Update for calamares openSUSE-SU-2019:2628-1 (calamares)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-12/msg00017.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the calamares
  package(s) announced via the openSUSE-SU-2019:2628_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for calamares fixes the following issues:

  - Launch with pkexec calamares in openSUSE Tumbleweed, but launch with
  'xdg-su -c calamares' in openSUSE Leap 15.

  Update to Calamares 3.2.15:

  - 'displaymanager' module now treats 'sysconfig' as a regular entry in the
  'displaymanagers' list, and the 'sysconfigSetup' key is used as a
  shorthand to force only that entry in the list.

  - 'machineid' module has been re-written in C++ and extended with a new
  configuration key to generate urandom pool data.

  - 'unpackfs' now supports a special 'sourcefs' value of file for copying
  single files (optionally with renaming) or directory trees to the target
  system.

  - 'unpackfs' now support an 'exclude' and 'excludeFile' setting for
  excluding particular files or patters from unpacking.

  Update to Calamares 3.2.14:

  - 'locale' module no longer recognizes the legacy GeoIP configuration.
  This has been deprecated since Calamares 3.2.8 and is now removed.

  - 'packagechooser' module can now be custom-labeled in the overall
  progress (left-hand column).

  - 'displaymanager' module now recognizes KDE Plasma 5.17.

  - 'displaymanager' module now can handle Wayland sessions and can detect
  sessions from their .desktop files.

  - 'unpackfs' now has special handling for sourcefs setting file.

  Update to Calamares 3.2.13.

  Update to Calamares 3.2.11:

  - Fix race condition in modules/luksbootkeyfile/main.py (boo#1140256,
  CVE-2019-13178)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2628=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2628=1");

  script_tag(name:"affected", value:"calamares package(s) on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"calamares", rpm:"calamares~3.2.15~lp150.7.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"calamares-debuginfo", rpm:"calamares-debuginfo~3.2.15~lp150.7.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"calamares-debugsource", rpm:"calamares-debugsource~3.2.15~lp150.7.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"calamares-webview", rpm:"calamares-webview~3.2.15~lp150.7.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"calamares-webview-debuginfo", rpm:"calamares-webview-debuginfo~3.2.15~lp150.7.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"calamares-branding-upstream", rpm:"calamares-branding-upstream~3.2.15~lp150.7.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
