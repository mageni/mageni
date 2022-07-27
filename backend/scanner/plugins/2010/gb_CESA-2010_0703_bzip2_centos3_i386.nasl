###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for bzip2 CESA-2010:0703 centos3 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "bzip2 is a freely available, high-quality data compressor. It provides both
  standalone compression and decompression utilities, as well as a shared
  library for use with other programs.

  An integer overflow flaw was discovered in the bzip2 decompression routine.
  This issue could, when decompressing malformed archives, cause bzip2, or an
  application linked against the libbz2 library, to crash or, potentially,
  execute arbitrary code. (CVE-2010-0405)
  
  Users of bzip2 should upgrade to these updated packages, which contain a
  backported patch to resolve this issue. All running applications using the
  libbz2 library must be restarted for the update to take effect.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "bzip2 on CentOS 3";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-September/017014.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314019");
  script_version("$Revision: 8269 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-02 08:28:22 +0100 (Tue, 02 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-27 08:14:44 +0200 (Mon, 27 Sep 2010)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0405");
  script_name("CentOS Update for bzip2 CESA-2010:0703 centos3 i386");

  script_tag(name: "summary" , value: "Check for the Version of bzip2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"bzip2", rpm:"bzip2~1.0.2~14.EL3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bzip2-devel", rpm:"bzip2-devel~1.0.2~14.EL3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bzip2-libs", rpm:"bzip2-libs~1.0.2~14.EL3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
