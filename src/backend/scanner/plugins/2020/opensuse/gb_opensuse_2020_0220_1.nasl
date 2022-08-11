# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853039");
  script_version("2020-02-20T11:12:08+0000");
  script_cve_id("CVE-2019-15613", "CVE-2019-15621", "CVE-2019-15623", "CVE-2019-15624", "CVE-2020-8118", "CVE-2020-8119");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-02-20 11:12:08 +0000 (Thu, 20 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-16 04:00:32 +0000 (Sun, 16 Feb 2020)");
  script_name("openSUSE: Security Advisory for nextcloud (openSUSE-SU-2020:0220-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00020.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nextcloud'
  package(s) announced via the openSUSE-SU-2020:0220-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nextcloud fixes the following issues:

  Nextcloud was updated to 15.0.14:

  - NC-SA-2020-002, CVE-2019-15613: workflow rules to depend their behaviour
  on the file extension when checking file mimetypes  (boo#1162766)

  - NC-SA-2019-016, CVE-2019-15623: Exposure of Private Information caused
  the server to send it's domain and user IDs to the Nextcloud Lookup
  Server without any further data when the Lookup server is disabled
  (boo#1162775)

  - NC-SA-2019-015, CVE-2019-15624: Improper Input Validation allowed group
  admins to create users with IDs of system folders (boo#1162776)

  - NC-SA-2019-012, CVE-2020-8119: Improper authorization caused leaking of
  previews and files when a file-drop share link is opened via the gallery
  app (boo#1162781)

  - NC-SA-2019-014, CVE-2020-8118: An authenticated server-side request
  forgery allowed to detect local and remote services when adding a new
  subscription in the calendar application (boo#1162782)

  - NC-SA-2020-012, CVE-2019-15621: Improper permissions preservation causes
  sharees to be able to reshare with write permissions when sharing the
  mount point of a share they received, as a public link (boo#1162784)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-220=1

  - openSUSE Backports SLE-15-SP1:

  zypper in -t patch openSUSE-2020-220=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2020-220=1

  - SUSE Package Hub for SUSE Linux Enterprise 12:

  zypper in -t patch openSUSE-2020-220=1");

  script_tag(name:"affected", value:"'nextcloud' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"nextcloud", rpm:"nextcloud~15.0.14~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
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
