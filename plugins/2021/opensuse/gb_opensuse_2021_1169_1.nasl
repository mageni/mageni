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
  script_oid("1.3.6.1.4.1.25623.1.0.854076");
  script_version("2021-08-24T09:58:36+0000");
  script_cve_id("CVE-2021-38385");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-08-25 10:27:37 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-20 06:51:53 +0000 (Fri, 20 Aug 2021)");
  script_name("openSUSE: Security Advisory for tor (openSUSE-SU-2021:1169-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1169-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PMWWIBVBPI5X7QIC5VO3NJURIXL33ROT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tor'
  package(s) announced via the openSUSE-SU-2021:1169-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tor fixes the following issues:

     tor 0.4.6.7:

  * Fix a DoS via a remotely triggerable assertion failure (boo#1189489,
       TROVE-2021-007, CVE-2021-38385)

     tor 0.4.6.6:

  * Fix a compilation error with gcc 7, drop tor-0.4.6.5-gcc7.patch

  * Enable the deterministic RNG for unit tests that covers the address set
       bloomfilter-based API&#x27 s

     tor 0.4.6.5

  * Add controller support for creating v3 onion services with client auth

  * When voting on a relay with a Sybil-like appearance, add the Sybil flag
       when clearing out the other flags. This lets a relay
       operator know why their relay hasn&#x27 t been included in the consensus

  * Relays now report how overloaded they are

  * Add a new DoS subsystem to control the rate of client connections for
       relays

  * Relays now publish statistics about v3 onions services

  * Improve circuit timeout algorithm for client performance");

  script_tag(name:"affected", value:"'tor' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"tor", rpm:"tor~0.4.6.7~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tor-debuginfo", rpm:"tor-debuginfo~0.4.6.7~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tor-debugsource", rpm:"tor-debugsource~0.4.6.7~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
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