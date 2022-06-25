###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2013_1556_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for chromium openSUSE-SU-2013:1556-1 (chromium)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850536");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-11-19 14:05:59 +0530 (Tue, 19 Nov 2013)");
  script_cve_id("CVE-2013-2906", "CVE-2013-2907", "CVE-2013-2908", "CVE-2013-2909",
                "CVE-2013-2910", "CVE-2013-2911", "CVE-2013-2912", "CVE-2013-2913",
                "CVE-2013-2914", "CVE-2013-2915", "CVE-2013-2916", "CVE-2013-2917",
                "CVE-2013-2918", "CVE-2013-2919", "CVE-2013-2920", "CVE-2013-2921",
                "CVE-2013-2922", "CVE-2013-2923", "CVE-2013-2924");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("SuSE Update for chromium openSUSE-SU-2013:1556-1 (chromium)");
  script_tag(name:"affected", value:"chromium on openSUSE 12.2");
  script_tag(name:"insight", value:"Update to Chromium 30.0.1599.66:

  - Easier searching by image

  - A number of new apps/extension APIs

  - Lots of under the hood changes for stability and
  performance

  - Security fixes:
  + CVE-2013-2906: Races in Web Audio
  + CVE-2013-2907: Out of bounds read in Window.prototype
  object
  + CVE-2013-2908: Address bar spoofing related to the
  204 No Content status code
  + CVE-2013-2909: Use after free in inline-block rendering
  + CVE-2013-2910: Use-after-free in Web Audio
  + CVE-2013-2911: Use-after-free in XSLT
  + CVE-2013-2912: Use-after-free in PPAPI
  + CVE-2013-2913: Use-after-free in XML document parsing
  + CVE-2013-2914: Use after free in the Windows color
  chooser   dialog
  + CVE-2013-2915: Address bar spoofing via a malformed
  scheme
  + CVE-2013-2916: Address bar spoofing related to the 204
  No  Content status code
  + CVE-2013-2917: Out of bounds read in Web Audio
  + CVE-2013-2918: Use-after-free in DOM
  + CVE-2013-2919: Memory corruption in V8
  + CVE-2013-2920: Out of bounds read in URL parsing
  + CVE-2013-2921: Use-after-free in resource loader
  + CVE-2013-2922: Use-after-free in template element
  + CVE-2013-2923: Various fixes from internal audits,
  fuzzing and  other initiatives
  + CVE-2013-2924: Use-after-free in ICU. Upstream bug

  - Add patch chromium-fix-altgrkeys.diff

  - Make sure that AltGr is treated correctly
  (issue#296835)

  - Do not build with system libxml (bnc#825157)

  - Update to Chromium 31.0.1640.0

  * Bug and Stability Fixes

  - Fix destkop file for chromium by removing extension from
  icon

  - Change the methodology for the Chromium packages. Build
  is now based on an official tarball. As soon as the Beta
  channel catches up with the current version, Chromium
  will be  based on the Beta channel instead of svn
  snapshots

  - Update to 31.0.1632

  * Bug and Stability fixes

  - Added the flag --enable-threaded-compositing to the
  startup  script. This flag seems to be required when
  hardware acceleration is in use. This prevents websites
  from locking up on users in certain cases.

  - Update to 31.0.1627

  * Bug and Stability fixes

  - Update to 31.0.1619

  * bug and Stability fixes

  - require mozilla-nss-devel  = 3.14 and mozilla-nspr-devel
   = 4.9.5

  - Add patch exclude_ymp.diff to ensure that 1-click-install
  files  are downloaded and NOT opened (bnc#836059)

  - Update to 31.0.1611

  * Bug and stability fixes

  - Update to 31.0.1605

  * Bug and stability fixes

  - Change the startup script so that Chromium will not
  start  when the chrome_sandbox doesn't have the SETUID.
  (bnc#779 ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.2");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE12.2")
{

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~30.0.1599.66~1.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~30.0.1599.66~1.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~30.0.1599.66~1.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~30.0.1599.66~1.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~30.0.1599.66~1.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~30.0.1599.66~1.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~30.0.1599.66~1.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~30.0.1599.66~1.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~30.0.1599.66~1.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-suid-helper", rpm:"chromium-suid-helper~30.0.1599.66~1.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-suid-helper-debuginfo", rpm:"chromium-suid-helper-debuginfo~30.0.1599.66~1.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
