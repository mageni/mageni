###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_0592_slf4j_centos7.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for slf4j CESA-2018:0592 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882865");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-03-28 08:51:24 +0200 (Wed, 28 Mar 2018)");
  script_cve_id("CVE-2018-8088");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for slf4j CESA-2018:0592 centos7");

  script_tag(name:"summary", value:"Check the version of slf4j");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Simple Logging Facade for Java or
  (SLF4J) is a simple facade for various logging APIs allowing the end-user to
  plug in the desired implementation at deployment time. SLF4J also allows for
  a gradual migration path away from Jakarta Commons Logging (JCL).

  Security Fix(es):

  * slf4j: Deserialisation vulnerability in EventData constructor can allow
  for arbitrary code execution (CVE-2018-8088)

  For more details about the security issue(s), including the impact, a CVSS
  score, and other related information, refer to the CVE page(s) listed in
  the References section.

  Red Hat would like to thank Chris McCown for reporting this issue.");

  script_tag(name:"affected", value:"slf4j on CentOS 7");

  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-March/022811.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"slf4j", rpm:"slf4j~1.7.4~4.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slf4j-javadoc", rpm:"slf4j-javadoc~1.7.4~4.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slf4j-manual", rpm:"slf4j-manual~1.7.4~4.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
