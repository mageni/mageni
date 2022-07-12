###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_973_1.nasl 8356 2018-01-10 08:00:39Z teissa $
#
# Ubuntu Update for koffice vulnerabilities USN-973-1
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
tag_insight = "Will Dormann, Alin Rad Pop, Braden Thomas, and Drew Yao discovered that the
  Xpdf used in KOffice contained multiple security issues in its JBIG2
  decoder. If a user or automated system were tricked into opening a crafted
  PDF file, an attacker could cause a denial of service or execute arbitrary
  code with privileges of the user invoking the program. (CVE-2009-0146,
  CVE-2009-0147, CVE-2009-0166, CVE-2009-0799, CVE-2009-0800, CVE-2009-1179,
  CVE-2009-1180, CVE-2009-1181)

  It was discovered that the Xpdf used in KOffice contained multiple security
  issues when parsing malformed PDF documents. If a user or automated system
  were tricked into opening a crafted PDF file, an attacker could cause a
  denial of service or execute arbitrary code with privileges of the user
  invoking the program. (CVE-2009-3606, CVE-2009-3608, CVE-2009-3609)

  KOffice in Ubuntu 9.04 uses a very old version of Xpdf to import PDFs into
  KWord. Upstream KDE no longer supports PDF import in KOffice and as a
  result it was dropped in Ubuntu 9.10. While an attempt was made to fix the
  above issues, the maintenance burden for supporting this very old version
  of Xpdf outweighed its utility, and PDF import is now also disabled in
  Ubuntu 9.04.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-973-1";
tag_affected = "koffice vulnerabilities on Ubuntu 9.04";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-973-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.314245");
  script_version("$Revision: 8356 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 09:00:39 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-20 14:57:11 +0200 (Fri, 20 Aug 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-3606", "CVE-2009-3608", "CVE-2009-3609");
  script_name("Ubuntu Update for koffice vulnerabilities USN-973-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU9.04")
{

  if ((res = isdpkgvuln(pkg:"karbon", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kchart", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kexi", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kformula", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kivio", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"koffice-dbg", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"koffice-dev", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"koffice-libs", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"koshell", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kplato", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kpresenter", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krita", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kspread", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kthesaurus", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kugar", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kword", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kivio-data", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"koffice-data", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"koffice-doc-html", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"koffice-doc", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"koffice", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kpresenter-data", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krita-data", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kword-data", ver:"1.6.3-7ubuntu6.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
