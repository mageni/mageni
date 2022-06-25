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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0174");
  script_cve_id("CVE-2016-1548", "CVE-2016-1550", "CVE-2016-2516", "CVE-2016-2518");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-10 13:15:00 +0000 (Thu, 10 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2016-0174)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0174");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0174.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18378");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0082/");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0084/");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/SecurityNotice#April_2016_NTP_4_2_8p7_Security");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/IFPKQDCJCLLEPK5D5RBOGCBNDW5TNIBM/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the MGASA-2016-0174 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated ntp packages fix security vulnerabilities:

It is possible to change the time of an ntpd client or deny service to an ntpd
client by forcing it to change from basic client/server mode to interleaved
symmetric mode. An attacker can spoof a packet from a legitimate ntpd server
with an origin timestamp that matches the peer->dst timestamp recorded for that
server. After making this switch, the client will reject all future legitimate
server responses. It is possible to force the victim client to move time after
the mode has been changed. ntpq gives no indication that the mode has been
switched (CVE-2016-1548).

An exploitable vulnerability exists in the message authentication functionality
of Network Time Protocol libntp. An attacker can send a series of crafted
messages to attempt to recover the message digest key (CVE-2016-1550).

If ntpd was expressly configured to allow for remote configuration, a
malicious user who knows the controlkey for ntpq or the requestkey for ntpdc
(if mode7 is expressly enabled) can create a session with ntpd and if an
existing association is unconfigured using the same IP twice on the unconfig
directive line, ntpd will abort (CVE-2016-2516).

Using a crafted packet to create a peer association with hmode > 7 causes the
MATCH_ASSOC() lookup to make an out-of-bounds reference (CVE-2016-2518).

Note that CVE-2016-2516, as well as other known but unfixed vulnerabilities
in ntpd, are also mitigated by not allowing remote configuration, which is
the default in Mageia.");

  script_tag(name:"affected", value:"'ntp' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~24.5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-client", rpm:"ntp-client~4.2.6p5~24.5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~24.5.mga5", rls:"MAGEIA5"))) {
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
