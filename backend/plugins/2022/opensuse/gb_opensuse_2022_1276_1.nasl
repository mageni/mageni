# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.854604");
  script_version("2022-04-29T06:36:55+0000");
  script_cve_id("CVE-2022-26495", "CVE-2022-26496");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-29 10:20:12 +0000 (Fri, 29 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-21 01:01:12 +0000 (Thu, 21 Apr 2022)");
  script_name("openSUSE: Security Advisory for nbd (SUSE-SU-2022:1276-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1276-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GY3FXWPGNBOFA2QZOFDFNU2AZJWYEW7A");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nbd'
  package(s) announced via the SUSE-SU-2022:1276-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nbd fixes the following issues:

  - CVE-2022-26495: Fixed an integer overflow with a resultant heap-based
       buffer overflow (bsc#1196827).

  - CVE-2022-26496: Fixed a stack-based buffer overflow when parsing the
       name field by sending a crafted NBD_OPT_INFO (bsc#1196828).
  Update to version 3.24 (bsc#1196827, bsc#1196828, CVE-2022-26495,
     CVE-2022-26496):

  * Don't overwrite the hostname with the TLS hostname
  Update to version 3.22:

  - nbd-server: handle auth for v6-mapped IPv4 addresses

  - nbd-client.c: parse the next option in all cases

  - configure.ac: silence a few autoconf 2.71 warnings

  - spec: Relax NBD_OPT_LIST_META_CONTEXTS

  - client: Don't confuse Unix socket with TLS hostname

  - server: Avoid deprecated g_memdup
  Update to version 3.21:

  - Fix --disable-manpages build

  - Fix a bug in whitespace handling regarding authorization files

  - Support client-side marking of devices as read-only

  - Support preinitialized NBD connection (i.e., skip the negotiation).

  - Fix the systemd unit file for nbd-client so it works with netlink (the
         more common situation nowadays)
  Update to 3.20.0 (no changelog)
  Update to version 3.19.0:

  * Better error messages in case of unexpected disconnects

  * Better compatibility with non-bash sh implementations (for
         configure.sh)

  * Fix for a segfault in NBD_OPT_INFO handling

  * The ability to specify whether to listen on both TCP and Unix domain
         sockets, rather than to always do so

  * Various minor editorial and spelling fixes in the documentation.
  Update to version 1.18.0:

  * Client: Add the '-g' option to avoid even trying the NBD_OPT_GO message

  * Server: fixes to inetd mode

  * Don't make gnutls and libnl automagic.

  * Server: bugfixes in handling of some export names during verification.

  * Server: clean supplementary groups when changing user.

  * Client: when using the netlink protocol, only set a timeout when there
         actually is a timeout, rather than defaulting to 0 seconds

  * Improve documentation on the nbdtab file

  * Minor improvements to some error messages

  * Improvements to test suite so it works better on non-GNU userland
         environments

  - Update to version 1.17.0:

  * proto: add xNBD command NBD_CMD_CACHE to the spec

  * server: do not crash when handling child name

  * server: Close socket pair when fork fails");

  script_tag(name:"affected", value:"'nbd' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"nbd", rpm:"nbd~3.24~150000.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbd-debuginfo", rpm:"nbd-debuginfo~3.24~150000.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbd-debugsource", rpm:"nbd-debugsource~3.24~150000.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"nbd", rpm:"nbd~3.24~150000.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbd-debuginfo", rpm:"nbd-debuginfo~3.24~150000.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbd-debugsource", rpm:"nbd-debugsource~3.24~150000.3.3.1", rls:"openSUSELeap15.3"))) {
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
