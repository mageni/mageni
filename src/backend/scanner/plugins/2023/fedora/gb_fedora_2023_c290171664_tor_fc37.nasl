# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.823156");
  script_version("2023-01-26T10:11:56+0000");
  script_cve_id("CVE-2023-23589");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-26 10:11:56 +0000 (Thu, 26 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-25 02:02:12 +0000 (Wed, 25 Jan 2023)");
  script_name("Fedora: Security Advisory for tor (FEDORA-2023-c290171664)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-c290171664");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZMY4FWXYKP3MDXTZ3EJ7XJVGBCKBK2XL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tor'
  package(s) announced via the FEDORA-2023-c290171664 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Tor network is a group of volunteer-operated servers that allows people to
improve their privacy and security on the Internet. Tor&#39, s users employ this
network by connecting through a series of virtual tunnels rather than making a
direct connection, thus allowing both organizations and individuals to share
information over public networks without compromising their privacy. Along the
same line, Tor is an effective censorship circumvention tool, allowing its
users to reach otherwise blocked destinations or content. Tor can also be used
as a building block for software developers to create new communication tools
with built-in privacy features.

This package contains the Tor software that can act as either a server on the
Tor network, or as a client to connect to the Tor network.");

  script_tag(name:"affected", value:"'tor' package(s) on Fedora 37.");

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

if(release == "FC37") {

  if(!isnull(res = isrpmvuln(pkg:"tor", rpm:"tor~0.4.7.13~1.fc37", rls:"FC37"))) {
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