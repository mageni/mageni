###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for jasper CESA-2017:1208 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882713");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-05-16 06:50:02 +0200 (Tue, 16 May 2017)");
  script_cve_id("CVE-2015-5203", "CVE-2015-5221", "CVE-2016-10248", "CVE-2016-10249",
                "CVE-2016-10251", "CVE-2016-1577", "CVE-2016-1867", "CVE-2016-2089",
                "CVE-2016-2116", "CVE-2016-8654", "CVE-2016-8690", "CVE-2016-8691",
                "CVE-2016-8692", "CVE-2016-8693", "CVE-2016-8883", "CVE-2016-8884",
                "CVE-2016-8885", "CVE-2016-9262", "CVE-2016-9387", "CVE-2016-9388",
                "CVE-2016-9389", "CVE-2016-9390", "CVE-2016-9391", "CVE-2016-9392",
                "CVE-2016-9393", "CVE-2016-9394", "CVE-2016-9560", "CVE-2016-9583",
                "CVE-2016-9591", "CVE-2016-9600");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for jasper CESA-2017:1208 centos6");
  script_tag(name:"summary", value:"Check the version of jasper");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"JasPer is an implementation of Part 1 of
  the JPEG 2000 image compression standard.

Security Fix(es):

Multiple flaws were found in the way JasPer decoded JPEG 2000 image files.
A specially crafted file could cause an application using JasPer to crash
or, possibly, execute arbitrary code.


Multiple flaws were found in the way JasPer decoded JPEG 2000 image files.
A specially crafted file could cause an application using JasPer to crash.


Red Hat would like to thank Liu Bingchang (IIE) for reporting");
  script_tag(name:"affected", value:"jasper on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-May/022408.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"jasper", rpm:"jasper~1.900.1~21.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jasper-devel", rpm:"jasper-devel~1.900.1~21.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jasper-libs", rpm:"jasper-libs~1.900.1~21.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jasper-utils", rpm:"jasper-utils~1.900.1~21.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
