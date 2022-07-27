# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.883239");
  script_version("2020-05-27T04:05:03+0000");
  script_cve_id("CVE-2019-12519", "CVE-2019-12525", "CVE-2020-11945");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-05-27 09:35:59 +0000 (Wed, 27 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-22 03:01:04 +0000 (Fri, 22 May 2020)");
  script_name("CentOS: Security Advisory for squid (CESA-2020:2040)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2020-May/035741.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid'
  package(s) announced via the CESA-2020:2040 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Squid is a high-performance proxy caching server for web clients,
supporting FTP, Gopher, and HTTP data objects.

Security Fix(es):

  * squid: improper check for new member in ESIExpression::Evaluate allows
for stack buffer overflow (CVE-2019-12519)

  * squid: improper access restriction upon Digest Authentication nonce
replay could lead to remote code execution (CVE-2020-11945)

  * squid: parsing of header Proxy-Authentication leads to memory corruption
(CVE-2019-12525)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'squid' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~3.5.20~15.el7_8.1", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-migration-script", rpm:"squid-migration-script~3.5.20~15.el7_8.1", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-sysvinit", rpm:"squid-sysvinit~3.5.20~15.el7_8.1", rls:"CentOS7"))) {
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