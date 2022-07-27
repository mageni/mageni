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
  script_oid("1.3.6.1.4.1.25623.1.0.821010");
  script_version("2022-07-07T10:16:06+0000");
  script_cve_id("CVE-2022-1996", "CVE-2022-24675", "CVE-2022-28327", "CVE-2022-27191", "CVE-2022-29526", "CVE-2022-30629", "CVE-2022-21698");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-07-07 10:16:06 +0000 (Thu, 07 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-16 12:54:00 +0000 (Thu, 16 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-07-06 01:44:34 +0000 (Wed, 06 Jul 2022)");
  script_name("Fedora: Security Advisory for dnscrypt-proxy (FEDORA-2022-fae3ecee19)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-fae3ecee19");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PJHZMHCJNFWOYYRG6ZEMNCOTJEUSBF7C");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnscrypt-proxy'
  package(s) announced via the FEDORA-2022-fae3ecee19 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flexible DNS proxy, with support for modern encrypted DNS protocols such as
DNSCrypt v2 and DNS-over-HTTP/2.

Features:

  - DNS traffic encryption and authentication. Supports DNS-over-HTTPS (DoH)
 and DNSCrypt.

  - DNSSEC compatible

  - DNS query monitoring, with separate log files for regular and suspicious
 queries

  - Pattern-based local blocking of DNS names and IP addresses

  - Time-based filtering, with a flexible weekly schedule

  - Transparent redirection of specific domains to specific resolvers

  - DNS caching, to reduce latency and improve privacy

  - Local IPv6 blocking to reduce latency on IPv4-only networks

  - Load balancing: pick a set of resolvers, dnscrypt-proxy will automatically
 measure and keep track of their speed, and balance the traffic across the
 fastest available ones.

  - Cloaking: like a HOSTS file on steroids, that can return preconfigured
 addresses for specific names, or resolve and return the IP address of other
 names. This can be used for local development as well as to enforce safe
 search results on Google, Yahoo and Bing.

  - Automatic background updates of resolvers lists

  - Can force outgoing connections to use TCP, useful with tunnels such as Tor.");

  script_tag(name:"affected", value:"'dnscrypt-proxy' package(s) on Fedora 36.");

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

if(release == "FC36") {

  if(!isnull(res = isrpmvuln(pkg:"dnscrypt-proxy", rpm:"dnscrypt-proxy~2.1.1~4.fc36", rls:"FC36"))) {
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