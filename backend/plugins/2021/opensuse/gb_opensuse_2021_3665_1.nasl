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
  script_oid("1.3.6.1.4.1.25623.1.0.854304");
  script_version("2021-11-29T04:48:32+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-11-29 10:38:15 +0000 (Mon, 29 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-18 02:03:52 +0000 (Thu, 18 Nov 2021)");
  script_name("openSUSE: Security Advisory for drbd-utils (openSUSE-SU-2021:3665-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:3665-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OTZPTDVSROTODVKJ22XXXS3E33HLFZPE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'drbd-utils'
  package(s) announced via the openSUSE-SU-2021:3665-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for drbd-utils fixes the following issues:

  - make all binaries position independent (basc#1185132).

  - Upgrade to 9.0.18 (bsc#1189363)

  * build: remove rpm related targets

  * drbdsetup, v84: fix minor compile warnings

  * systemd: resource specific activation

  * systemd: drbd-reactor promoter templates

  * doc: fix maximum ping timeout

  * doc: add man pages for the systemd templates

  * drbdadm, v9: fix dstate for diskless volumes

  * build/release: use lbvers.py

  * drbd-attr: don&#x27 t leak fd to drbdsetup

  * doc: various fixes and additions

  * drbdsetup, events2, v9: add backing_device

  * build, Debian: rm dh-systemd dependency

  * drbdsetup, events2, v9: fix --poll regression

  * build, Debian: rm mail recommends

  * drbdsetup, events2, v9: allow --poll without --now

  * drbdsetup, invalidate: allow bitmap based resync after verify

  * drbdadm, sh-ll-dev: change output to 'none' if diskless

  * drbdadm, v9: allow set-gi in single node clusters

  * drbsetup, events2, v9: diff(erential) output

  * drbsetup, events2, v9: add --full output

  * v9: allow resource rename, also in drbdmon

  * drbdadm, v9: allow c-max-rate to be disabled

  * New drbd-attr Pacemaker RA

  * events2: handle mixed initial state and multicast events

  * events2: fix regression to always print resync done

  - Prepare &#x27 /usr&#x27  merge. (bsc#1029961)");

  script_tag(name:"affected", value:"'drbd-utils' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"drbd-utils", rpm:"drbd-utils~9.18.0~4.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drbd-utils-debuginfo", rpm:"drbd-utils-debuginfo~9.18.0~4.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drbd-utils-debugsource", rpm:"drbd-utils-debugsource~9.18.0~4.7.2", rls:"openSUSELeap15.3"))) {
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
