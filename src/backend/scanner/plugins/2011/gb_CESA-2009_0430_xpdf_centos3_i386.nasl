###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for xpdf CESA-2009:0430 centos3 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-April/015784.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880830");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166", "CVE-2009-0799",
                "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181",
                "CVE-2009-1182", "CVE-2009-1183");
  script_name("CentOS Update for xpdf CESA-2009:0430 centos3 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xpdf'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS3");
  script_tag(name:"affected", value:"xpdf on CentOS 3");
  script_tag(name:"insight", value:"Xpdf is an X Window System based viewer for Portable Document Format (PDF)
  files.

  Multiple integer overflow flaws were found in Xpdf's JBIG2 decoder. An
  attacker could create a malicious PDF file that would cause Xpdf to crash
  or, potentially, execute arbitrary code when opened. (CVE-2009-0147,
  CVE-2009-1179)

  Multiple buffer overflow flaws were found in Xpdf's JBIG2 decoder. An
  attacker could create a malicious PDF file that would cause Xpdf to crash
  or, potentially, execute arbitrary code when opened. (CVE-2009-0146,
  CVE-2009-1182)

  Multiple flaws were found in Xpdf's JBIG2 decoder that could lead to the
  freeing of arbitrary memory. An attacker could create a malicious PDF file
  that would cause Xpdf to crash or, potentially, execute arbitrary code when
  opened. (CVE-2009-0166, CVE-2009-1180)

  Multiple input validation flaws were found in Xpdf's JBIG2 decoder. An
  attacker could create a malicious PDF file that would cause Xpdf to crash
  or, potentially, execute arbitrary code when opened. (CVE-2009-0800)

  Multiple denial of service flaws were found in Xpdf's JBIG2 decoder. An
  attacker could create a malicious PDF that would cause Xpdf to crash when
  opened. (CVE-2009-0799, CVE-2009-1181, CVE-2009-1183)

  Red Hat would like to thank Braden Thomas and Drew Yao of the Apple Product
  Security team, and Will Dormann of the CERT/CC for responsibly reporting
  these flaws.

  Users are advised to upgrade to this updated package, which contains
  backported patches to correct these issues.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"xpdf", rpm:"xpdf~2.02~14.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
