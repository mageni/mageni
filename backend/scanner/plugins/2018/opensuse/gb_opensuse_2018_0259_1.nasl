###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0259_1.nasl 12523 2018-11-26 09:24:07Z mmartin $
#
# SuSE Update for chromium openSUSE-SU-2018:0259-1 (chromium)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851692");
  script_version("$Revision: 12523 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-26 10:24:07 +0100 (Mon, 26 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-01-29 07:47:09 +0100 (Mon, 29 Jan 2018)");
  script_cve_id("CVE-2017-15420", "CVE-2018-6031", "CVE-2018-6032", "CVE-2018-6033",
                "CVE-2018-6034", "CVE-2018-6035", "CVE-2018-6036", "CVE-2018-6037",
                "CVE-2018-6038", "CVE-2018-6039", "CVE-2018-6040", "CVE-2018-6041",
                "CVE-2018-6042", "CVE-2018-6043", "CVE-2018-6045", "CVE-2018-6046",
                "CVE-2018-6047", "CVE-2018-6048", "CVE-2018-6049", "CVE-2018-6050",
                "CVE-2018-6051", "CVE-2018-6052", "CVE-2018-6053", "CVE-2018-6054");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for chromium openSUSE-SU-2018:0259-1 (chromium)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for chromium to 64.0.3282.119 fixes several issues.

  These security issues were fixed:

  - CVE-2018-6031: Use after free in PDFium (boo#1077571)

  - CVE-2018-6032: Same origin bypass in Shared Worker (boo#1077571)

  - CVE-2018-6033: Race when opening downloaded files (boo#1077571)

  - CVE-2018-6034: Integer overflow in Blink (boo#1077571)

  - CVE-2018-6035: Insufficient isolation of devtools from extensions
  (boo#1077571)

  - CVE-2018-6036: Integer underflow in WebAssembly (boo#1077571)

  - CVE-2018-6037: Insufficient user gesture requirements in autofill
  (boo#1077571)

  - CVE-2018-6038: Heap buffer overflow in WebGL (boo#1077571)

  - CVE-2018-6039: XSS in DevTools (boo#1077571)

  - CVE-2018-6040: Content security policy bypass (boo#1077571)

  - CVE-2018-6041: URL spoof in Navigation (boo#1077571)

  - CVE-2018-6042: URL spoof in OmniBox (boo#1077571)

  - CVE-2018-6043: Insufficient escaping with external URL handlers
  (boo#1077571)

  - CVE-2018-6045: Insufficient isolation of devtools from extensions
  (boo#1077571)

  - CVE-2018-6046: Insufficient isolation of devtools from extensions
  (boo#1077571)

  - CVE-2018-6047: Cross origin URL leak in WebGL (boo#1077571)

  - CVE-2018-6048: Referrer policy bypass in Blink (boo#1077571)

  - CVE-2017-15420: URL spoofing in Omnibox (boo#1077571)

  - CVE-2018-6049: UI spoof in Permissions (boo#1077571)

  - CVE-2018-6050: URL spoof in OmniBox (boo#1077571)

  - CVE-2018-6051: Referrer leak in XSS Auditor (boo#1077571)

  - CVE-2018-6052: Incomplete no-referrer policy implementation (boo#1077571)

  - CVE-2018-6053: Leak of page thumbnails in New Tab Page (boo#1077571)

  - CVE-2018-6054: Use after free in WebUI (boo#1077571)

  Re was updated to version 2018-01-01 (boo#1073323)");
  script_tag(name:"affected", value:"chromium on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-01/msg00079.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"libre2-0-20180101", rpm:"libre2-0-20180101~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libre2-0-debuginfo-20180101", rpm:"libre2-0-debuginfo-20180101~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"re2-debugsource-20180101", rpm:"re2-debugsource-20180101~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"re2-devel-20180101", rpm:"re2-devel-20180101~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~64.0.3282.119~135.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~64.0.3282.119~135.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~64.0.3282.119~135.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~64.0.3282.119~135.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~64.0.3282.119~135.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libre2-0-32bit-20180101", rpm:"libre2-0-32bit-20180101~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libre2-0-debuginfo-32bit-20180101", rpm:"libre2-0-debuginfo-32bit-20180101~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
