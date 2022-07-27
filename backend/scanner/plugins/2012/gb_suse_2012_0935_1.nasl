###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_0935_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for seamonkey openSUSE-SU-2012:0935-1 (seamonkey)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850240");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-12-13 17:02:05 +0530 (Thu, 13 Dec 2012)");
  script_cve_id("CVE-2012-1948", "CVE-2012-1949", "CVE-2012-1951", "CVE-2012-1952",
                "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957",
                "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1960", "CVE-2012-1961",
                "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1967");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for seamonkey openSUSE-SU-2012:0935-1 (seamonkey)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'seamonkey'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.4|openSUSE12\.1)");
  script_tag(name:"affected", value:"seamonkey on openSUSE 12.1, openSUSE 11.4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Seamonkey was updated to version 2.11 (bnc#771583)

  * MFSA 2012-42/CVE-2012-1949/CVE-2012-1948 Miscellaneous
  memory safety hazards

  * MFSA
  2012-44/CVE-2012-1951/CVE-2012-1954/CVE-2012-1953/CVE-2012-1
  952 Gecko memory corruption

  * MFSA 2012-45/CVE-2012-1955 (bmo#757376) Spoofing issue
  with location

  * MFSA 2012-47/CVE-2012-1957 (bmo#750096) Improper
  filtering of javascript in HTML feed-view

  * MFSA 2012-48/CVE-2012-1958 (bmo#750820) use-after-free
  in nsGlobalWindow::PageHidden

  * MFSA 2012-49/CVE-2012-1959 (bmo#754044, bmo#737559)
  Same-compartment Security Wrappers can be bypassed

  * MFSA 2012-50/CVE-2012-1960 (bmo#761014) Out of bounds
  read in QCMS

  * MFSA 2012-51/CVE-2012-1961 (bmo#761655) X-Frame-Options
  header ignored when duplicated

  * MFSA 2012-52/CVE-2012-1962 (bmo#764296)
  JSDependentString::undepend string conversion results
  in memory corruption

  * MFSA 2012-53/CVE-2012-1963 (bmo#767778) Content
  Security Policy 1.0 implementation errors cause data
  leakage

  * MFSA 2012-56/CVE-2012-1967 (bmo#758344) Code execution
  through javascript: URLs

  * relicensed to MPL-2.0

  - updated/removed patches

  - requires NSS 3.13.5

  - update to Seamonkey 2.10.1");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.11~24.3", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-debuginfo", rpm:"seamonkey-debuginfo~2.11~24.3", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-debugsource", rpm:"seamonkey-debugsource~2.11~24.3", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.11~24.3", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.11~24.3", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-translations-common", rpm:"seamonkey-translations-common~2.11~24.3", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-translations-other", rpm:"seamonkey-translations-other~2.11~24.3", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~2.11~24.3", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSE12.1")
{

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.11~2.24.2", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-debuginfo", rpm:"seamonkey-debuginfo~2.11~2.24.2", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-debugsource", rpm:"seamonkey-debugsource~2.11~2.24.2", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.11~2.24.2", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.11~2.24.2", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-translations-common", rpm:"seamonkey-translations-common~2.11~2.24.2", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-translations-other", rpm:"seamonkey-translations-other~2.11~2.24.2", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~2.11~2.24.2", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
