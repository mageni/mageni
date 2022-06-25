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
  script_oid("1.3.6.1.4.1.25623.1.0.854064");
  script_version("2021-08-24T09:58:36+0000");
  script_cve_id("CVE-2021-27358", "CVE-2021-27962", "CVE-2021-28146", "CVE-2021-28147", "CVE-2021-28148");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-08-25 10:27:37 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-13 03:01:34 +0000 (Fri, 13 Aug 2021)");
  script_name("openSUSE: Security Advisory for grafana (openSUSE-SU-2021:2662-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:2662-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CQXNKFCX2C74T7LPZZCRD6GK2WWJTT4B");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grafana'
  package(s) announced via the openSUSE-SU-2021:2662-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for grafana fixes the following issues:

  - CVE-2021-27358: unauthenticated remote attackers to trigger a Denial of
       Service via a remote API call (bsc#1183803)

  - Update to version 7.5.7:

  * Updated relref to 'Configuring exemplars' section (#34240) (#34243)

  * Added exemplar topic (#34147) (#34226)

  * Quota: Do not count folders towards dashboard quota (#32519) (#34025)

  * Instructions to separate emails with semicolons (#32499) (#34138)

  * Docs: Remove documentation of v8 generic OAuth feature (#34018)

  * Annotations: Prevent orphaned annotation tags cleanup when no
         annotations were cleaned (#33957) (#33975)

  * [GH-33898] Add missing --no-cache to Dockerfile. (#33906) (#33935)

  * ReleaseNotes: Updated changelog and release notes for 7.5.6 (#33932)
         (#33936)

  * Stop hoisting @icons/material (#33922)

  * Chore: fix react-color version in yarn.lock (#33914)

  * 'Release: Updated versions in package to 7.5.6' (#33909)

  * Loki: fix label browser crashing when + typed (#33900) (#33901)

  * Document `hide_version` flag (#33670) (#33881)

  * Add isolation level db configuration parameter (#33830) (#33878)

  * Sanitize PromLink button (#33874) (#33876)

  * Docs feedback: /administration/provisioning.md (#33804) (#33842)

  * Docs: delete from high availability docs references to removed
         configurations related to session storage (#33827) (#33851)

  * Docs: Update _index.md (#33797) (#33799)

  * Docs: Update installation.md (#33656) (#33703)

  * GraphNG: uPlot 1.6.9 (#33598) (#33612)

  * dont consider invalid email address a failed email (#33671) (#33681)

  * InfluxDB: Improve measurement-autocomplete behavior in query editor
         (#33494) (#33625)

  * add template for dashboard url parameters  (#33549) (#33588)

  * Add note to Snapshot API doc to specify that user has to provide the
         entire dashboard model  (#33572) (#33586)

  * Update team.md (#33454) (#33536)

  * Removed duplicate file 'dashboard_folder_permissions.md (#33497)

  * Document customQueryParameters for prometheus datasource provisioning
         (#33440) (#33495)

  * ReleaseNotes: Updated changelog and release notes for 7.5.5 (#33473)
         (#33492)

  * Documentation: Update developer-guide.md (#33478) (#33490 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'grafana' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"grafana", rpm:"grafana~7.5.7~3.12.1", rls:"openSUSELeap15.3"))) {
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
