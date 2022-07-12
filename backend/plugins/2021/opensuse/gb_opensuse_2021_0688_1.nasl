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
  script_oid("1.3.6.1.4.1.25623.1.0.853806");
  script_version("2021-05-25T12:16:58+0000");
  script_cve_id("CVE-2021-21404");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-05-26 10:26:09 +0000 (Wed, 26 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-12 03:03:17 +0000 (Wed, 12 May 2021)");
  script_name("openSUSE: Security Advisory for syncthing (openSUSE-SU-2021:0688-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0688-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UIFNGMDOIZ3DQYLTSKXQFICFKTHWOLKM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'syncthing'
  package(s) announced via the openSUSE-SU-2021:0688-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for syncthing fixes the following issues:

     Update to 1.15.0/1.15.1

  * This release fixes a vulnerability where Syncthing and the relay
         server can crash due to malformed relay protocol messages
         (CVE-2021-21404)  see GHSA-x462-89pf-6r5h. (boo#1184428)

  * This release updates the CLI to use subcommands and adds the
         subcommands cli (previously standalone stcli utility) and decrypt (for
         offline verifying and decrypting encrypted folders).

  * With this release we invite everyone to test the 'untrusted
         (encrypted) devices' feature. You should not use it yet on important
         production data. Thus UI controls are hidden behind a feature flag.
         For more information, visit:
     Update to 1.14.0

  * This release adds configurable device and folder defaults.

  * The output format of the /rest/db/browse endpoint has changed.

     update to 1.13.1:

  * Bugfixes

  * Official builds of v1.13.0 come with the Tech Ui, which is impossible
         to switch back from

     update to 1.12.1:

  * Invalid names are allowed and 'auto accepted' in folder root path on
         Windows

  * Sometimes indexes for some folders aren&#x27 t sent after starting Syncthing

  * [Untrusted] Remove Unexpected Items leaves things behind

  * Wrong theme on selection

  * Quic spamming address resolving

  * Deleted locally changed items still shown as locally changed

  * Allow specifying remote expected web UI port which would generate a
         href somewhere

  * Ignore fsync errors when saving ignore files

     Update to 1.12.0

  - The 1.12.0 release

  - adds a new config REST API.

  - The 1.11.0 release

  - adds the sendFullIndexOnUpgrade option to control whether all index
           data is resent when an upgrade is detected, equivalent to starting
           Syncthing with --reset-deltas. ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'syncthing' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"syncthing", rpm:"syncthing~1.15.1~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syncthing-relaysrv", rpm:"syncthing-relaysrv~1.15.1~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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
