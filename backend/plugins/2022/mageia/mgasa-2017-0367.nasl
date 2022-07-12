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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0367");
  script_cve_id("CVE-2017-13704", "CVE-2017-14491", "CVE-2017-14492", "CVE-2017-14493", "CVE-2017-14494", "CVE-2017-14495", "CVE-2017-14496");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-11 01:29:00 +0000 (Fri, 11 May 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0367)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0367");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0367.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19528");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21793");
  script_xref(name:"URL", value:"https://wiki.mozilla.org/images/f/f7/Dnsmasq-report.pdf");
  script_xref(name:"URL", value:"https://docs.google.com/document/d/14y2kiXgB69fLBY0xuMeqc-YiZg4UDCw2xd4-mZspoP8");
  script_xref(name:"URL", value:"http://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2017q3/011692.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4TK6DWC53WSU6633EVZL7H4PCWBYHMHK/");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2017:2836");
  script_xref(name:"URL", value:"https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsmasq' package(s) announced via the MGASA-2017-0367 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An audit by mozilla security found several vulnerability and potential
vulnerability in dnsmasq:
- Uninitialized buffer leads to memory leakage
- Allocated memory is not cleared
- Unchecked return value can lead to NULL pointer dereference
- Hardcoded values in fscanf() format strings with aliased buffers

CVE-2017-13704: Dnsmasq could be made to crash on a large DNS query: A
DNS query received by UDP which exceeds 512 bytes (or the EDNS0 packet
size, if different.) is enough to cause SIGSEGV. (bug 21793)

CVE-2017-14491: A heap buffer overflow was found in dnsmasq in the code
responsible for building DNS replies. An attacker could send crafted DNS
packets to dnsmasq which would cause it to crash or, potentially,
execute arbitrary code.

CVE-2017-14492: A heap buffer overflow was discovered in dnsmasq in the
IPv6 router advertisement (RA) handling code. An attacker on the local
network segment could send crafted RAs to dnsmasq which would cause it
to crash or, potentially, execute arbitrary code. This issue only
affected configurations using one of these options: enable-ra, ra-only,
slaac, ra-names, ra-advrouter, or ra-stateless.

CVE-2017-14493: A stack buffer overflow was found in dnsmasq in the
DHCPv6 code. An attacker on the local network could send a crafted
DHCPv6 request to dnsmasq which would cause it to a crash or,
potentially, execute arbitrary code.

CVE-2017-14494: An information leak was found in dnsmasq in the
DHCPv6 relay code. An attacker on the local network could send crafted
DHCPv6 packets to dnsmasq causing it to forward the contents of process
memory, potentially leaking sensitive data.

CVE-2017-14495: A memory exhaustion flaw was found in dnsmasq in the
EDNS0 code. An attacker could send crafted DNS packets which would
trigger memory allocations which would never be freed, leading to
unbounded memory consumption and eventually a crash. This issue only
affected configurations using one of the options: add-mac, add-cpe-id,
or add-subnet.

CVE-2017-14496: An integer underflow flaw leading to a buffer
over-read was found in dnsmasq in the EDNS0 code. An attacker could
send crafted DNS packets to dnsmasq which would cause it to crash.
This issue only affected configurations using one of the options:
add-mac, add-cpe-id, or add-subnet.");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq", rpm:"dnsmasq~2.77~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq-base", rpm:"dnsmasq-base~2.77~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq-utils", rpm:"dnsmasq-utils~2.77~1.1.mga5", rls:"MAGEIA5"))) {
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
