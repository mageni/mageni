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
  script_oid("1.3.6.1.4.1.25623.1.0.883293");
  script_version("2020-11-19T07:38:10+0000");
  script_cve_id("CVE-2020-11078");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-11-19 11:32:07 +0000 (Thu, 19 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-19 04:01:18 +0000 (Thu, 19 Nov 2020)");
  script_name("CentOS: Security Advisory for resource-agents (CESA-2020:5004)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2020:5004");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2020-November/035836.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'resource-agents'
  package(s) announced via the CESA-2020:5004 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The resource-agents packages provide the Pacemaker and RGManager service
managers with a set of scripts. These scripts interface with several
services to allow operating in a high-availability (HA) environment.

Security Fix(es):

  * python-httplib2: CRLF injection via an attacker controlled unescaped part
of uri for httplib2.Http.request function (CVE-2020-11078)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * gcp-vpc-move-vip: An existing alias IP range is removed when a second
alias IP range is added (BZ#1846732)

  * sybaseASE: Resource fails to complete a probe operation without access to
$sybase_home [RHEL 7] (BZ#1848673)

  * azure-lb: Resource fails intermittently due to nc output redirection to
pidfile (BZ#1850779)

  * azure-events: handle exceptions in urlopen (RHEL7) (BZ#1862121)");

  script_tag(name:"affected", value:"'resource-agents' package(s) on CentOS 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"resource-agents", rpm:"resource-agents~4.1.1~61.el7_9.4", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resource-agents-aliyun", rpm:"resource-agents-aliyun~4.1.1~61.el7_9.4", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resource-agents-gcp", rpm:"resource-agents-gcp~4.1.1~61.el7_9.4", rls:"CentOS7"))) {
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