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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0390");
  script_cve_id("CVE-2021-22116", "CVE-2021-32718", "CVE-2021-32719");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-19 20:15:00 +0000 (Mon, 19 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0390)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0390");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0390.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29174");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rabbitmq-server' package(s) announced via the MGASA-2021-0390 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated rabbitmq-server packages fix security vulnerabilities:

RabbitMQ all versions prior to 3.8.16 are prone to a denial of service
vulnerability due to improper input validation in AMQP 1.0 client
connection endpoint. A malicious user can exploit the vulnerability by
sending malicious AMQP messages to the target RabbitMQ instance having
the AMQP 1.0 plugin enabled (CVE-2021-22116).

RabbitMQ is a multi-protocol messaging broker. In rabbitmq-server prior
to version 3.8.17, a new user being added via management UI could lead
to the user's bane being rendered in a confirmation message without proper
'<script>' tag sanitization, potentially allowing for JavaScript code
execution in the context of the page. In order for this to occur, the user
must be signed in and have elevated permissions (other user management)
(CVE-2021-32718).

RabbitMQ is a multi-protocol messaging broker. In rabbitmq-server prior
to version 3.8.18, when a federation link was displayed in the RabbitMQ
management UI via the 'rabbitmq_federation_management' plugin, its consumer
tag was rendered without proper <script> tag sanitization. This potentially
allows for JavaScript code execution in the context of the page. The user
must be signed in and have elevated permissions (manage federation
upstreams and policies) for this to occur (CVE-2021-32719).");

  script_tag(name:"affected", value:"'rabbitmq-server' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"rabbitmq-server", rpm:"rabbitmq-server~3.8.18~1.mga8", rls:"MAGEIA8"))) {
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
