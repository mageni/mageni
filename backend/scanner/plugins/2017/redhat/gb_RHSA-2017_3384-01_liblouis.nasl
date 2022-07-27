###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_3384-01_liblouis.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# RedHat Update for liblouis RHSA-2017:3384-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.812339");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-12-07 07:37:30 +0100 (Thu, 07 Dec 2017)");
  script_cve_id("CVE-2017-15101", "CVE-2014-8184");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for liblouis RHSA-2017:3384-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'liblouis'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Liblouis is an open source braille
translator and back-translator named in honor of Louis Braille. It features support
for computer and literary braille, supports contracted and uncontracted translation
for many languages and has support for hyphenation. New languages can easily be
added through tables that support a rule or dictionary based approach.
Liblouis also supports math braille (Nemeth and Marburg).

Security Fix(es):

  * A missing fix for one stack-based buffer overflow in findTable() for
CVE-2014-8184 was discovered. An attacker could cause denial of service or
potentially allow arbitrary code execution. (CVE-2017-15101)

Red Hat would like to thank Samuel Thibault for reporting this issue.");
  script_tag(name:"affected", value:"liblouis on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-December/msg00005.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"liblouis-python", rpm:"liblouis-python~2.5.2~12.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblouis", rpm:"liblouis~2.5.2~12.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblouis-debuginfo", rpm:"liblouis-debuginfo~2.5.2~12.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
