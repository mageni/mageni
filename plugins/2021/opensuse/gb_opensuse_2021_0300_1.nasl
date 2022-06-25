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
  script_oid("1.3.6.1.4.1.25623.1.0.853684");
  script_version("2021-04-21T07:29:02+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 04:59:57 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for mumble (openSUSE-SU-2021:0300-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0300-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TRBUKSNSCDTY3U6LK6SUQ3QWJS3JDGST");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mumble'
  package(s) announced via the openSUSE-SU-2021:0300-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mumble fixes the following issues:

     mumble was updated to 1.3.4:

  * Fix use of outdated (non-existent) notification icon names

  * Fix Security vulnerability caused by allowing non http/https URL schemes
       in public server list (boo#1182123)

  * Server: Fix Exit status for actions like --version or --supw

  * Fix packet loss &amp  audio artifacts caused by OCB2 XEX* mitigation

  - update apparmor profiles to get warning free again on 15.2

  - use abstractions for ssl files

  - allow inet dgram sockets as mumble can also work via udp

  - allow netlink socket (probably for dbus)

  - properly allow lsb_release again

  - add support for optional local include

  - start murmurd directly as user mumble-server it gets rid of the
       dac_override/setgid/setuid/chown permissions

     Update to upstream version 1.3.3

     Client:

  * Fixed: Chatbox invisible (zero height) (#4388)

  * Fixed: Handling of invalid packet sizes (#4394)

  * Fixed: Race-condition leading to loss of shortcuts (#4430)

  * Fixed: Link in About dialog is now clickable again (#4454)

  * Fixed: Sizing issues in ACL-Editor (#4455)

  * Improved: PulseAudio now always samples at 48 kHz (#4449)

     Server:

  * Fixed: Crash due to problems when using PostgreSQL (#4370)

  * Fixed: Handling of invalid package sizes (#4392)");

  script_tag(name:"affected", value:"'mumble' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"mumble", rpm:"mumble~1.3.4~lp152.2.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-debuginfo", rpm:"mumble-debuginfo~1.3.4~lp152.2.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-debugsource", rpm:"mumble-debugsource~1.3.4~lp152.2.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-server", rpm:"mumble-server~1.3.4~lp152.2.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-server-debuginfo", rpm:"mumble-server-debuginfo~1.3.4~lp152.2.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-32bit", rpm:"mumble-32bit~1.3.4~lp152.2.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-32bit-debuginfo", rpm:"mumble-32bit-debuginfo~1.3.4~lp152.2.6.1", rls:"openSUSELeap15.2"))) {
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
