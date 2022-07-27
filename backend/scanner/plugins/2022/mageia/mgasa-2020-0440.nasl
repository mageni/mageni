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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0440");
  script_cve_id("CVE-2017-17742", "CVE-2019-16201", "CVE-2019-16254", "CVE-2019-16255", "CVE-2019-8320", "CVE-2019-8321", "CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324", "CVE-2019-8325", "CVE-2020-25613");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0440)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0440");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0440.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27402");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2330");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2392");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25875");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27402");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jruby' package(s) announced via the MGASA-2020-0440 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Response Splitting attack in the HTTP server of WEBrick (CVE-2017-17742).

Delete directory using symlink when decompressing tar (CVE-2019-8320).

Escape sequence injection vulnerability in verbose (CVE-2019-8321).

Escape sequence injection vulnerability in gem owner (CVE-2019-8322).

Escape sequence injection vulnerability in API response handling (CVE-2019-8323).

Installing a malicious gem may lead to arbitrary code execution
(CVE-2019-8324).

Escape sequence injection vulnerability in errors (CVE-2019-8325).

Regular Expression Denial of Service vulnerability of WEBrick's Digest access
authentication (CVE-2019-16201).

HTTP Response Splitting attack in the HTTP server of WEBrick (CVE-2019-16254).

Code injection vulnerability (CVE-2019-16255).

A potential HTTP request smuggling vulnerability in WEBrick was reported.
WEBrick (bundled along with jruby) was too tolerant against an invalid
Transfer-Encoding header. This may lead to inconsistent interpretation between
WEBrick and some HTTP proxy servers, which may allow the attacker to 'smuggle'
a request (CVE-2020-25613).");

  script_tag(name:"affected", value:"'jruby' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"jruby", rpm:"jruby~1.7.22~7.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jruby-devel", rpm:"jruby-devel~1.7.22~7.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jruby-javadoc", rpm:"jruby-javadoc~1.7.22~7.2.mga7", rls:"MAGEIA7"))) {
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
