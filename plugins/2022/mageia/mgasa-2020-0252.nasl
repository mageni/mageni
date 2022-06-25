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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0252");
  script_cve_id("CVE-2019-16782", "CVE-2020-8161");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-05 23:15:00 +0000 (Mon, 05 Oct 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0252)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0252");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0252.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26688");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25915");
  script_xref(name:"URL", value:"https://github.com/rack/rack/security/advisories/GHSA-hrqr-hxpp-chr3");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/HZXMWILCICQLA2BYSP6I2CRMUG53YBLX/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2216");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby-rack' package(s) announced via the MGASA-2020-0252 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated ruby-rack packages fix security vulnerabilities:

There's a possible information leak / session hijack vulnerability in
Rack(RubyGem rack). Attackers may be able to find and hijack sessions
by using timing attacks targeting the session id. Session ids are usually
stored and indexed in a database that uses some kind of scheme for
speeding up lookups of that session id. By carefully measuring the amount
of time it takes to look up a session, an attacker may be able to find a
valid session id and hijack the session. The session id itself may be
generated randomly, but the way the session is indexed by the backing
store does not use a secure comparison (CVE-2019-16782).

If certain directories exist in a director that is managed by
Rack::Directory, an attacker could, using this vulnerability, read the
contents of files on the server that were outside of the root specified
in the Rack::Directory initializer (CVE-2020-8161).");

  script_tag(name:"affected", value:"'ruby-rack' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"ruby-rack", rpm:"ruby-rack~2.0.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rack-doc", rpm:"ruby-rack-doc~2.0.8~1.mga7", rls:"MAGEIA7"))) {
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
