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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1555");
  script_version("2020-01-23T12:13:57+0000");
  script_cve_id("CVE-2014-9293", "CVE-2014-9295", "CVE-2015-1799", "CVE-2015-5194", "CVE-2015-5219", "CVE-2015-7692", "CVE-2015-7702", "CVE-2015-7704", "CVE-2015-7977", "CVE-2015-8138", "CVE-2015-8139", "CVE-2015-8158", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1550", "CVE-2016-4954", "CVE-2016-7426", "CVE-2016-9310", "CVE-2017-6462", "CVE-2017-6464");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 12:13:57 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:13:57 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for ntp (EulerOS-SA-2019-1555)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1555");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'ntp' package(s) announced via the EulerOS-SA-2019-1555 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that when ntp is configured with rate limiting for all associations the limits are also applied to responses received from its configured sources. A remote attacker who knows the sources can cause a denial of service by preventing ntpd from accepting valid responses from its sources.(CVE-2016-7426)

ntpq in NTP before 4.2.8p7 allows remote attackers to obtain origin timestamps and then impersonate peers via unspecified vectors.(CVE-2015-8139)

A NULL pointer dereference flaw was found in the way ntpd processed 'ntpdc reslist' commands that queried restriction lists with a large amount of entries. A remote attacker could potentially use this flaw to crash ntpd.(CVE-2015-7977)

A vulnerability was found in NTP, in the parsing of packets from the /dev/datum device. A malicious device could send crafted messages, causing ntpd to crash.(CVE-2017-6462)

The process_packet function in ntp_proto.c in ntpd in NTP 4.x before 4.2.8p8 allows remote attackers to cause a denial of service (peer-variable modification) by sending spoofed packets from many source IP addresses in a certain scenario, as demonstrated by triggering an incorrect leap indication.(CVE-2016-4954)

It was found that ntpd could crash due to an uninitialized variable when processing malformed logconfig configuration commands.(CVE-2015-5194)

It was discovered that the sntp utility could become unresponsive due to being caught in an infinite loop when processing a crafted NTP packet.(CVE-2015-5219)

It was discovered that ntpd as a client did not correctly check the originate timestamp in received packets. A remote attacker could use this flaw to send a crafted packet to an ntpd client that would effectively disable synchronization with the server, or push arbitrary offset/delay measurements to modify the time on the client.(CVE-2015-8138)

It was found that the fix for CVE-2014-9750 was incomplete: three issues were found in the value length checks in NTP's ntp_crypto.c, where a packet with particular autokey operations that contained malicious data was not always being completely validated. A remote attacker could use a specially crafted NTP packet to crash ntpd.(CVE-2015-7702)

Multiple buffer overflow flaws were discovered in ntpd's crypto_recv(), ctl_putdata(), and configure() functions. A remote attacker could use either of these flaws to send a specially crafted request packet that could crash ntpd or, potentially, execute arbitrary code with the privileges of the ntp user. Note: the crypto_recv() flaw requires non default configurations to be active, while the ctl_putdata() flaw, by default, can only be ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'ntp' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~28.h8", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~28.h8", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sntp", rpm:"sntp~4.2.6p5~28.h8", rls:"EULEROSVIRT-3.0.1.0"))) {
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