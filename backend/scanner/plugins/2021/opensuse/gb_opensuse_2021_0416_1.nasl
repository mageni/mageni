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
  script_oid("1.3.6.1.4.1.25623.1.0.853583");
  script_version("2021-04-21T07:29:02+0000");
  script_cve_id("CVE-2021-26675", "CVE-2021-26676");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 04:55:26 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for connman (openSUSE-SU-2021:0416-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0416-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OTS3LYTIBT7XMBIAK6RCJOKOTPNIEQSF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'connman'
  package(s) announced via the openSUSE-SU-2021:0416-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for connman fixes the following issues:

     Update to 1.39 (boo#1181751):

  * Fix issue with scanning state synchronization and iwd.

  * Fix issue with invalid key with 4-way handshake offloading.

  * Fix issue with DNS proxy length checks to prevent buffer overflow.
       (CVE-2021-26675)

  * Fix issue with DHCP leaking stack data via uninitialized variable.
       (CVE-2021-26676)

     Update to 1.38:

  * Fix issue with online check on IP address update.

  * Fix issue with OpenVPN and encrypted private keys.

  * Fix issue with finishing of VPN connections.

  * Add support for updated stable iwd APIs.

  * Add support for WireGuard networks.

     Update to 1.37:

  * Fix issue with handling invalid gateway addresses.

  * Fix issue with handling updates of default gateway.

  * Fix issue with DHCP servers that require broadcast flag.

  * Add support for option to use gateways as time servers.

  * Add support for option to select default technology.

  * Add support for Address Conflict Detection (ACD).

  * Add support for IPv6 iptables management.

     Change in 1.36:

  * Fix issue with DNS short response on error handling.

  * Fix issue with handling incoming DNS requests.

  * Fix issue with handling empty timeserver list.

  * Fix issue with incorrect DHCP byte order.

  * Fix issue with AllowDomainnameUpdates handling.

  * Fix issue with IPv4 link-local IP conflict error.

  * Fix issue with handling WISPr over TLS connections.

  * Fix issue with WiFi background scanning handling.

  * Fix issue with WiFi disconnect+connect race condition.

  * Fix issue with WiFi scanning and tethering operation.

  * Fix issue with WiFi security change handling.

  * Fix issue with missing signal for WPS changes.

  * Fix issue with online check retry handling.

  * Add support for systemd-resolved backend.

  * Add support for mDNS configuration setup.");

  script_tag(name:"affected", value:"'connman' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"connman", rpm:"connman~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-client", rpm:"connman-client~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-client-debuginfo", rpm:"connman-client-debuginfo~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-debuginfo", rpm:"connman-debuginfo~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-debugsource", rpm:"connman-debugsource~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-devel", rpm:"connman-devel~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-doc", rpm:"connman-doc~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-nmcompat", rpm:"connman-nmcompat~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-hh2serial-gps", rpm:"connman-plugin-hh2serial-gps~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-hh2serial-gps-debuginfo", rpm:"connman-plugin-hh2serial-gps-debuginfo~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-iospm", rpm:"connman-plugin-iospm~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-iospm-debuginfo", rpm:"connman-plugin-iospm-debuginfo~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-l2tp", rpm:"connman-plugin-l2tp~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-l2tp-debuginfo", rpm:"connman-plugin-l2tp-debuginfo~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-openconnect", rpm:"connman-plugin-openconnect~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-openconnect-debuginfo", rpm:"connman-plugin-openconnect-debuginfo~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-openvpn", rpm:"connman-plugin-openvpn~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-openvpn-debuginfo", rpm:"connman-plugin-openvpn-debuginfo~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-polkit", rpm:"connman-plugin-polkit~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-pptp", rpm:"connman-plugin-pptp~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-pptp-debuginfo", rpm:"connman-plugin-pptp-debuginfo~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-tist", rpm:"connman-plugin-tist~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-tist-debuginfo", rpm:"connman-plugin-tist-debuginfo~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-vpnc", rpm:"connman-plugin-vpnc~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-vpnc-debuginfo", rpm:"connman-plugin-vpnc-debuginfo~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-wireguard", rpm:"connman-plugin-wireguard~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-wireguard-debuginfo", rpm:"connman-plugin-wireguard-debuginfo~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-test", rpm:"connman-test~1.39~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
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