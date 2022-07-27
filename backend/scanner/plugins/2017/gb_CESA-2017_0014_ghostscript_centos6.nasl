###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for ghostscript CESA-2017:0014 centos6
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
  script_oid("1.3.6.1.4.1.25623.1.0.882623");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-01-05 05:42:43 +0100 (Thu, 05 Jan 2017)");
  script_cve_id("CVE-2013-5653", "CVE-2016-7977", "CVE-2016-7979", "CVE-2016-8602");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for ghostscript CESA-2017:0014 centos6");
  script_tag(name:"summary", value:"Check the version of ghostscript");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Ghostscript suite contains utilities
for rendering PostScript and PDF documents. Ghostscript translates PostScript
code to common bitmap formats so that the code can be displayed or printed.

Security Fix(es):

  * It was found that the ghostscript functions getenv, filenameforall and
.libfile did not honor the -dSAFER option, usually used when processing
untrusted documents, leading to information disclosure. A specially crafted
postscript document could read environment variable, list directory and
retrieve file content respectively, from the target. (CVE-2013-5653,
CVE-2016-7977)

  * It was found that the ghostscript function .initialize_dsc_parser did not
validate its parameter before using it, allowing a type confusion flaw. A
specially crafted postscript document could cause a crash code execution in
the context of the gs process. (CVE-2016-7979)

  * It was found that ghostscript did not sufficiently check the validity of
parameters given to the .sethalftone5 function. A specially crafted
postscript document could cause a crash, or execute arbitrary code in the
context of the gs process. (CVE-2016-8602)");
  script_tag(name:"affected", value:"ghostscript on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-January/022191.html");
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

  if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~8.70~21.el6_8.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~8.70~21.el6_8.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~8.70~21.el6_8.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-gtk", rpm:"ghostscript-gtk~8.70~21.el6_8.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
