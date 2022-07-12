###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_0656_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for update openSUSE-SU-2012:0656-1 (update)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850270");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-12-13 17:01:53 +0530 (Thu, 13 Dec 2012)");
  script_cve_id("CVE-2011-3083", "CVE-2011-3084", "CVE-2011-3085", "CVE-2011-3086",
               "CVE-2011-3087", "CVE-2011-3088", "CVE-2011-3089", "CVE-2011-3090",
               "CVE-2011-3091", "CVE-2011-3092", "CVE-2011-3093", "CVE-2011-3094",
               "CVE-2011-3095", "CVE-2011-3096", "CVE-2011-3098", "CVE-2011-3100",
               "CVE-2011-3101", "CVE-2011-3102");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for update openSUSE-SU-2012:0656-1 (update)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'update'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.1");
  script_tag(name:"affected", value:"update on openSUSE 12.1");
  script_tag(name:"insight", value:"Chromium update to 21.0.1145

  * Fixed several issues around audio not playing with
  videos

  * Crash Fixes

  * Improvements to trackpad on Cr-48

  * Security Fixes (bnc#762481)

  - CVE-2011-3083: Browser crash with video + FTP

  - CVE-2011-3084: Load links from internal pages in
  their own process.

  - CVE-2011-3085: UI corruption with long autofilled
  values

  - CVE-2011-3086: Use-after-free with style element.

  - CVE-2011-3087: Incorrect window navigation

  - CVE-2011-3088: Out-of-bounds read in hairline drawing

  - CVE-2011-3089: Use-after-free in table handling.

  - CVE-2011-3090: Race condition with workers.

  - CVE-2011-3091: Use-after-free with indexed DB

  - CVE-2011-3092: Invalid write in v8 regex

  - CVE-2011-3093: Out-of-bounds read in glyph handling

  - CVE-2011-3094: Out-of-bounds read in Tibetan handling

  - CVE-2011-3095: Out-of-bounds write in OGG container.

  - CVE-2011-3096: Use-after-free in GTK omnibox handling.

  - CVE-2011-3098: Bad search path for Windows Media
  Player plug-in

  - CVE-2011-3100: Out-of-bounds read drawing dash paths.

  - CVE-2011-3101: Work around Linux Nvidia driver bug

  - CVE-2011-3102: Off-by-one out-of-bounds write in
  libxml.");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE12.1")
{

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~21.0.1145.0~1.23.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~21.0.1145.0~1.23.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~21.0.1145.0~1.23.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~21.0.1145.0~1.23.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~21.0.1145.0~1.23.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-suid-helper", rpm:"chromium-suid-helper~21.0.1145.0~1.23.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-suid-helper-debuginfo", rpm:"chromium-suid-helper-debuginfo~21.0.1145.0~1.23.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libv8-3", rpm:"libv8-3~3.11.3.0~1.27.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libv8-3-debuginfo", rpm:"libv8-3-debuginfo~3.11.3.0~1.27.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"v8-debugsource", rpm:"v8-debugsource~3.11.3.0~1.27.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"v8-devel", rpm:"v8-devel~3.11.3.0~1.27.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"v8-private-headers-devel", rpm:"v8-private-headers-devel~3.11.3.0~1.27.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
