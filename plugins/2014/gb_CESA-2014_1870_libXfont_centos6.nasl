###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libXfont CESA-2014:1870 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882086");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-11-19 06:35:25 +0100 (Wed, 19 Nov 2014)");
  script_cve_id("CVE-2014-0209", "CVE-2014-0210", "CVE-2014-0211");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for libXfont CESA-2014:1870 centos6");

  script_tag(name:"summary", value:"Check the version of libXfont");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The libXfont packages provide the X.Org
libXfont runtime library. X.Org is an open source implementation of the X Window
System.

A use-after-free flaw was found in the way libXfont processed certain font
files when attempting to add a new directory to the font path. A malicious,
local user could exploit this issue to potentially execute arbitrary code
with the privileges of the X.Org server. (CVE-2014-0209)

Multiple out-of-bounds write flaws were found in the way libXfont parsed
replies received from an X.org font server. A malicious X.org server could
cause an X client to crash or, possibly, execute arbitrary code with the
privileges of the X.Org server. (CVE-2014-0210, CVE-2014-0211)

Red Hat would like to thank the X.org project for reporting these issues.
Upstream acknowledges Ilja van Sprundel as the original reporter.

Users of libXfont should upgrade to these updated packages, which contain a
backported patch to resolve this issue. All running X.Org server instances
must be restarted for the update to take effect.");
  script_tag(name:"affected", value:"libXfont on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-November/020768.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"libXfont", rpm:"libXfont~1.4.5~4.el6_6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont-devel", rpm:"libXfont-devel~1.4.5~4.el6_6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
