###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for jasper RHSA-2017:1208-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871813");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-05-10 06:49:13 +0200 (Wed, 10 May 2017)");
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
  script_name("RedHat Update for jasper RHSA-2017:1208-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'jasper'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"JasPer is an implementation of Part 1 of the
  JPEG 2000 image compression standard.

Security Fix(es):

Multiple flaws were found in the way JasPer decoded JPEG 2000 image files.
A specially crafted file could cause an application using JasPer to crash
or, possibly, execute arbitrary code. (CVE-2016-8654, CVE-2016-9560,
CVE-2016-10249, CVE-2015-5203, CVE-2015-5221, CVE-2016-1577, CVE-2016-8690,
CVE-2016-8693, CVE-2016-8884, CVE-2016-8885, CVE-2016-9262, CVE-2016-9591)

Multiple flaws were found in the way JasPer decoded JPEG 2000 image files.
A specially crafted file could cause an application using JasPer to crash.
(CVE-2016-1867, CVE-2016-2089, CVE-2016-2116, CVE-2016-8691, CVE-2016-8692,
CVE-2016-8883, CVE-2016-9387, CVE-2016-9388, CVE-2016-9389, CVE-2016-9390,
CVE-2016-9391, CVE-2016-9392, CVE-2016-9393, CVE-2016-9394, CVE-2016-9583,
CVE-2016-9600, CVE-2016-10248, CVE-2016-10251)

Red Hat would like to thank Liu Bingchang (IIE) for reporting
CVE-2016-8654, CVE-2016-9583, CVE-2016-9591, and CVE-2016-9600  Gustavo
Grieco for reporting CVE-2015-5203  and Josselin Feist for reporting
CVE-2015-5221.");
  script_tag(name:"affected", value:"jasper on
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-May/msg00010.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(7|6)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"jasper-debuginfo", rpm:"jasper-debuginfo~1.900.1~30.el7_3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jasper-libs", rpm:"jasper-libs~1.900.1~30.el7_3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"jasper", rpm:"jasper~1.900.1~21.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jasper-debuginfo", rpm:"jasper-debuginfo~1.900.1~21.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jasper-libs", rpm:"jasper-libs~1.900.1~21.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
