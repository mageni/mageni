###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for icedtea-web MDVSA-2012:122 (icedtea-web)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:122");
  script_oid("1.3.6.1.4.1.25623.1.0.831710");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-08-03 11:19:16 +0530 (Fri, 03 Aug 2012)");
  script_cve_id("CVE-2012-3422", "CVE-2012-3423");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Mandriva Update for icedtea-web MDVSA-2012:122 (icedtea-web)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icedtea-web'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(2011\.0|mes5\.2)");
  script_tag(name:"affected", value:"icedtea-web on Mandriva Linux 2011.0,
  Mandriva Enterprise Server 5.2");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been discovered and corrected in
  icedtea-web:

  An uninitialized pointer use flaw was found in IcedTea-Web web
  browser plugin.  A malicious web page could use this flaw make
  IcedTea-Web browser plugin pass invalid pointer to a web browser.
  Depending on the browser used, it may cause the browser to crash or
  possibly execute arbitrary code (CVE-2012-3422).

  It was discovered that the IcedTea-Web web browser plugin incorrectly
  assumed that all strings provided by browser are NUL terminated,
  which is not guaranteed by the NPAPI (Netscape Plugin Application
  Programming Interface).  When used in a browser that does not NUL
  terminate NPVariant NPStrings, this could lead to buffer over-read
  or over-write, resulting in possible information leak, crash, or code
  execution (CVE-2012-3423).

  The updated packages have been upgraded to the 1.1.6 version which
  is not affected by these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"icedtea-web", rpm:"icedtea-web~1.1.6~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icedtea-web-javadoc", rpm:"icedtea-web-javadoc~1.1.6~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_mes5.2")
{

  if ((res = isrpmvuln(pkg:"icedtea-web", rpm:"icedtea-web~1.1.6~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icedtea-web-javadoc", rpm:"icedtea-web-javadoc~1.1.6~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
