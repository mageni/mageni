###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for python MDVSA-2010:215 (python)
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
tag_insight = "Multiple vulnerabilities was discovered and corrected in python:

  Buffer underflow in the rgbimg module in Python 2.5 allows remote
  attackers to cause a denial of service (application crash) via a large
  ZSIZE value in a black-and-white (aka B/W) RGB image that triggers
  an invalid pointer dereference (CVE-2009-4134).
  
  Integer overflow in rgbimgmodule.c in the rgbimg module in Python
  2.5 allows remote attackers to have an unspecified impact via a large
  image that triggers a buffer overflow.  NOTE: this vulnerability exists
  because of an incomplete fix for CVE-2008-3143.12 (CVE-2010-1449).
  
  Multiple buffer overflows in the RLE decoder in the rgbimg module in
  Python 2.5 allow remote attackers to have an unspecified impact via an
  image file containing crafted data that triggers improper processing
  within the (1) longimagedata or (2) expandrow function (CVE-2010-1450).
  
  The asyncore module in Python before 3.2 does not properly handle
  unsuccessful calls to the accept function, and does not have
  accompanying documentation describing how daemon applications should
  handle unsuccessful calls to the accept function, which makes it
  easier for remote attackers to conduct denial of service attacks that
  terminate these applications via network connections (CVE-2010-3492).
  
  Multiple race conditions in smtpd.py in the smtpd module in Python 2.6,
  2.7, 3.1, and 3.2 alpha allow remote attackers to cause a denial of
  service (daemon outage) by establishing and then immediately closing
  a TCP connection, leading to the accept function having an unexpected
  return value of None, an unexpected value of None for the address,
  or an ECONNABORTED, EAGAIN, or EWOULDBLOCK error, or the getpeername
  function having an ENOTCONN error, a related issue to CVE-2010-3492
  (CVE-2010-3493).
  
  Packages for 2009.0 are provided as of the Extended Maintenance
  Program. Please visit this link to learn more:
  http://store.mandriva.com/product_info.php?cPath=149&amp;products_id=490
  
  The updated packages have been patched to correct these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "python on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-10/msg00041.php");
  script_oid("1.3.6.1.4.1.25623.1.0.313345");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-16 14:49:48 +0100 (Tue, 16 Nov 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "MDVSA", value: "2010:215");
  script_cve_id("CVE-2009-4134", "CVE-2008-3143", "CVE-2010-1449", "CVE-2010-1450", "CVE-2010-3492", "CVE-2010-3493");
  script_name("Mandriva Update for python MDVSA-2010:215 (python)");

  script_tag(name: "summary" , value: "Check for the Version of python");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"libpython2.5", rpm:"libpython2.5~2.5.2~5.9mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpython2.5-devel", rpm:"libpython2.5-devel~2.5.2~5.9mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python", rpm:"python~2.5.2~5.9mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-base", rpm:"python-base~2.5.2~5.9mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-docs", rpm:"python-docs~2.5.2~5.9mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.5.2~5.9mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tkinter-apps", rpm:"tkinter-apps~2.5.2~5.9mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64python2.5", rpm:"lib64python2.5~2.5.2~5.9mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64python2.5-devel", rpm:"lib64python2.5-devel~2.5.2~5.9mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"libpython2.5", rpm:"libpython2.5~2.5.2~5.9mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpython2.5-devel", rpm:"libpython2.5-devel~2.5.2~5.9mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python", rpm:"python~2.5.2~5.9mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-base", rpm:"python-base~2.5.2~5.9mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-docs", rpm:"python-docs~2.5.2~5.9mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.5.2~5.9mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tkinter-apps", rpm:"tkinter-apps~2.5.2~5.9mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64python2.5", rpm:"lib64python2.5~2.5.2~5.9mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64python2.5-devel", rpm:"lib64python2.5-devel~2.5.2~5.9mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
