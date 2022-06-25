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
  script_oid("1.3.6.1.4.1.25623.1.0.878834");
  script_version("2021-01-22T06:41:37+0000");
  script_cve_id("CVE-2020-26262");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-01-22 11:28:48 +0000 (Fri, 22 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-20 04:02:03 +0000 (Wed, 20 Jan 2021)");
  script_name("Fedora: Security Advisory for coturn (FEDORA-2021-dee141fc61)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC33");

  script_xref(name:"FEDORA", value:"2021-dee141fc61");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/G54UIUFTEC6RLPOISMB6FUW7456SBZC4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'coturn'
  package(s) announced via the FEDORA-2021-dee141fc61 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Coturn TURN Server is a VoIP media traffic NAT traversal server and gateway.
It can be used as a general-purpose network traffic TURN server/gateway, too.

This implementation also includes some extra features. Supported RFCs:

TURN specs:

  - RFC 5766 - base TURN specs

  - RFC 6062 - TCP relaying TURN extension

  - RFC 6156 - IPv6 extension for TURN

  - Experimental DTLS support as client protocol.

STUN specs:

  - RFC 3489 - 'classic' STUN

  - RFC 5389 - base 'new' STUN specs

  - RFC 5769 - test vectors for STUN protocol testing

  - RFC 5780 - NAT behavior discovery support

The implementation fully supports the following client-to-TURN-server protocols:

  - UDP (per RFC 5766)

  - TCP (per RFC 5766 and RFC 6062)

  - TLS (per RFC 5766 and RFC 6062), TLS1.0/TLS1.1/TLS1.2

  - DTLS (experimental non-standard feature)

Supported relay protocols:

  - UDP (per RFC 5766)

  - TCP (per RFC 6062)

Supported user databases (for user repository, with passwords or keys, if
authentication is required):

  - SQLite

  - MySQL

  - PostgreSQL

  - Redis

Redis can also be used for status and statistics storage and notification.

Supported TURN authentication mechanisms:

  - long-term

  - TURN REST API (a modification of the long-term mechanism, for time-limited
  secret-based authentication, for WebRTC applications)

The load balancing can be implemented with the following tools (either one or a
combination of them):

  - network load-balancer server

  - DNS-based load balancing

  - built-in ALTERNATE-SERVER mechanism.");

  script_tag(name:"affected", value:"'coturn' package(s) on Fedora 33.");

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

if(release == "FC33") {

  if(!isnull(res = isrpmvuln(pkg:"coturn", rpm:"coturn~4.5.2~1.fc33", rls:"FC33"))) {
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