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
  script_oid("1.3.6.1.4.1.25623.1.0.892710");
  script_version("2021-07-20T03:00:19+0000");
  script_cve_id("CVE-2017-4965", "CVE-2017-4966", "CVE-2017-4967", "CVE-2019-11281", "CVE-2019-11287", "CVE-2021-22116");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-07-20 10:27:54 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-20 03:00:19 +0000 (Tue, 20 Jul 2021)");
  script_name("Debian LTS: Security Advisory for rabbitmq-server (DLA-2710-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/07/msg00011.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2710-1");
  script_xref(name:"Advisory-ID", value:"DLA-2710-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rabbitmq-server'
  package(s) announced via the DLA-2710-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in rabbitmq-server, a
message-broker software.

CVE-2017-4965

Several forms in the RabbitMQ management UI are vulnerable to XSS
attacks.

CVE-2017-4966

RabbitMQ management UI stores signed-in user credentials in a
browser's local storage without expiration, making it possible to
retrieve them using a chained attack

CVE-2017-4967

Several forms in the RabbitMQ management UI are vulnerable to XSS
attacks.

CVE-2019-11281

The virtual host limits page, and the federation management UI,
which do not properly sanitize user input. A remote authenticated
malicious user with administrative access could craft a cross site
scripting attack that would gain access to virtual hosts and
policy management information

CVE-2019-11287

The 'X-Reason' HTTP Header can be leveraged to insert a malicious
Erlang format string that will expand and consume the heap,
resulting in the server crashing.

CVE-2021-22116

A malicious user can exploit the vulnerability by sending
malicious AMQP messages to the target RabbitMQ instance.");

  script_tag(name:"affected", value:"'rabbitmq-server' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
3.6.6-1+deb9u1.

We recommend that you upgrade your rabbitmq-server packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"rabbitmq-server", ver:"3.6.6-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
