###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2019_0022_keepalived_centos7.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for keepalived CESA-2019:0022 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882991");
  script_version("$Revision: 14058 $");
  script_cve_id("CVE-2018-19115");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-01-07 04:00:17 +0100 (Mon, 07 Jan 2019)");
  script_name("CentOS Update for keepalived CESA-2019:0022 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-January/023140.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'keepalived'
  package(s) announced via the CESA-2019:0022 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The keepalived utility provides simple and robust facilities for load
balancing and high availability. The load balancing framework relies on the
well-known and widely used IP Virtual Server (IPVS) kernel module providing
layer-4 (transport layer) load balancing. Keepalived implements a set of
checkers to dynamically and adaptively maintain and manage a load balanced
server pool according to the health of the servers. Keepalived also
implements the Virtual Router Redundancy Protocol (VRRPv2) to achieve high
availability with director failover.

Security Fix(es):

  * keepalived: Heap-based buffer overflow when parsing HTTP status codes
allows for denial of service or possibly arbitrary code execution
(CVE-2018-19115)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.");

  script_tag(name:"affected", value:"keepalived on CentOS 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"keepalived", rpm:"keepalived~1.3.5~8.el7_6", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
