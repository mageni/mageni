###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2017_3111_liblouis_centos7.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for liblouis CESA-2017:3111 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882797");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-11-05 08:49:20 +0100 (Sun, 05 Nov 2017)");
  script_cve_id("CVE-2014-8184", "CVE-2017-13738", "CVE-2017-13740", "CVE-2017-13741",
                "CVE-2017-13742", "CVE-2017-13743", "CVE-2017-13744");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for liblouis CESA-2017:3111 centos7");
  script_tag(name:"summary", value:"Check the version of liblouis");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Liblouis is an open source braille
translator and back-translator named in honor of Louis Braille. It features
support for computer and literary braille, supports contracted and uncontracted
translation for many languages and has support for hyphenation. New languages
can easily be added through tables that support a rule or dictionary based
approach. Liblouis also supports math braille (Nemeth and Marburg).

Security Fix(es):

  * Multiple flaws were found in the processing of translation tables in
liblouis. An attacker could crash or potentially execute arbitrary code
using malicious translation tables. (CVE-2014-8184, CVE-2017-13738,
CVE-2017-13740, CVE-2017-13741, CVE-2017-13742, CVE-2017-13743,
CVE-2017-13744)

The CVE-2014-8184 issue was discovered by Raphael Sanchez Prudencio (Red
Hat).");
  script_tag(name:"affected", value:"liblouis on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-November/022612.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"liblouis", rpm:"liblouis~2.5.2~11.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblouis-devel", rpm:"liblouis-devel~2.5.2~11.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblouis-doc", rpm:"liblouis-doc~2.5.2~11.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblouis-python", rpm:"liblouis-python~2.5.2~11.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblouis-utils", rpm:"liblouis-utils~2.5.2~11.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
