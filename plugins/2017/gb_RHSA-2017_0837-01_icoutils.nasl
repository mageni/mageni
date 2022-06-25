###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for icoutils RHSA-2017:0837-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871790");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-03-23 05:46:46 +0100 (Thu, 23 Mar 2017)");
  script_cve_id("CVE-2017-5208", "CVE-2017-5332", "CVE-2017-5333", "CVE-2017-6009",
                "CVE-2017-6010", "CVE-2017-6011");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for icoutils RHSA-2017:0837-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'icoutils'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The icoutils are a set of programs for
extracting and converting images in Microsoft Windows icon and cursor files. These
files usually have the extension .ico or .cur, but they can also be embedded in
executables or libraries.

Security Fix(es):

  * Multiple vulnerabilities were found in icoutils, in the wrestool program.
An attacker could create a crafted executable that, when read by wrestool,
could result in memory corruption leading to a crash or potential code
execution. (CVE-2017-5208, CVE-2017-5333, CVE-2017-6009)

  * A vulnerability was found in icoutils, in the wrestool program. An
attacker could create a crafted executable that, when read by wrestool,
could result in failure to allocate memory or an over-large memcpy
operation, leading to a crash. (CVE-2017-5332)

  * Multiple vulnerabilities were found in icoutils, in the icotool program.
An attacker could create a crafted ICO or CUR file that, when read by
icotool, could result in memory corruption leading to a crash or potential
code execution. (CVE-2017-6010, CVE-2017-6011)");
  script_tag(name:"affected", value:"icoutils on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-March/msg00064.html");
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

  if ((res = isrpmvuln(pkg:"icoutils", rpm:"icoutils~0.31.3~1.el7_3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icoutils-debuginfo", rpm:"icoutils-debuginfo~0.31.3~1.el7_3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
