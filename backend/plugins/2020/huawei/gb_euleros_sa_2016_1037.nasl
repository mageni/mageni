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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2016.1037");
  script_version("2020-01-23T10:39:53+0000");
  script_cve_id("CVE-2014-3477", "CVE-2014-3532", "CVE-2014-3533", "CVE-2014-3635", "CVE-2014-3636", "CVE-2014-3637", "CVE-2014-3638", "CVE-2014-3639", "CVE-2014-7824", "CVE-2015-0245");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 10:39:53 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 10:39:53 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for dbus (EulerOS-SA-2016-1037)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP1");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1037");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'dbus' package(s) announced via the EulerOS-SA-2016-1037 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"dbus 1.3.0 before 1.6.22 and 1.8.x before 1.8.6, when running on Linux 2.6.37-rc4 or later, allows local users to cause a denial of service (system-bus disconnect of other services or applications) by sending a message containing a file descriptor, then exceeding the maximum recursion depth before the initial message is forwarded.(CVE-2014-3532)

dbus 1.3.0 before 1.6.22 and 1.8.x before 1.8.6 allows local users to cause a denial of service (disconnect) via a certain sequence of crafted messages that cause the dbus-daemon to forward a message containing an invalid file descriptor.(CVE-2014-3533)

D-Bus 1.4.x through 1.6.x before 1.6.30, 1.8.x before 1.8.16, and 1.9.x before 1.9.10 does not validate the source of ActivationFailure signals, which allows local users to cause a denial of service (activation failure error returned) by leveraging a race condition involving sending an ActivationFailure signal before systemd responds.(CVE-2015-0245)

D-Bus 1.3.0 through 1.6.x before 1.6.24 and 1.8.x before 1.8.8 allows local users to (1) cause a denial of service (prevention of new connections and connection drop) by queuing the maximum number of file descriptors or (2) cause a denial of service (disconnect) via multiple messages that combine to have more than the allowed number of file descriptors for a single sendmsg call.(CVE-2014-3636)

The dbus-daemon in D-Bus 1.2.x through 1.4.x, 1.6.x before 1.6.20, and 1.8.x before 1.8.4, sends an AccessDenied error to the service instead of a client when the client is prohibited from accessing the service, which allows local users to cause a denial of service (initialization failure and exit) or possibly conduct a side-channel attack via a D-Bus message to an inactive service.(CVE-2014-3477)

D-Bus 1.3.0 through 1.6.x before 1.6.24 and 1.8.x before 1.8.8 does not properly close connections for processes that have terminated, which allows local users to cause a denial of service via a D-bus message containing a D-Bus connection file descriptor.(CVE-2014-3637)

Off-by-one error in D-Bus 1.3.0 through 1.6.x before 1.6.24 and 1.8.x before 1.8.8, when running on a 64-bit system and the max_message_unix_fds limit is set to an odd number, allows local users to cause a denial of service (dbus-daemon crash) or possibly execute arbitrary code by sending one more file descriptor than the limit, which triggers a heap-based buffer overflow or an assertion failure.(CVE-2014-3635)

The bus_connections_check_reply function in config-parser.c in D-Bus before 1.6.24 and 1.8.x before 1.8.8 allows local users to cause a denial of service (CPU consumption) via a large number of  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'dbus' package(s) on Huawei EulerOS V2.0SP1.");

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

if(release == "EULEROS-2.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"dbus", rpm:"dbus~1.6.12~11.h10", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-devel", rpm:"dbus-devel~1.6.12~11.h10", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-libs", rpm:"dbus-libs~1.6.12~11.h10", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-x11", rpm:"dbus-x11~1.6.12~11.h10", rls:"EULEROS-2.0SP1"))) {
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