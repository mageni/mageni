###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_1151_1.nasl 14110 2019-03-12 09:28:23Z cfischer $
#
# SuSE Update for chromium openSUSE-SU-2014:1151-1 (chromium)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850614");
  script_version("$Revision: 14110 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 10:28:23 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-09-23 05:52:38 +0200 (Tue, 23 Sep 2014)");
  script_cve_id("CVE-2014-3168", "CVE-2014-3169", "CVE-2014-3170", "CVE-2014-3171",
                "CVE-2014-3172", "CVE-2014-3173", "CVE-2014-3174", "CVE-2014-3176",
                "CVE-2014-3177", "CVE-2014-3175");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for chromium openSUSE-SU-2014:1151-1 (chromium)");
  script_tag(name:"insight", value:"Chromium was updated to 37.0.2062.94 containing security Fixes
  (bnc#893720).

  A full list of changes is available in the referenced vendor log.

  This update includes 50 security fixes. Below, we highlight fixes that
  were either contributed by external researchers or particularly
  interesting. Please see the Chromium security page for more information.

  Critical CVE-2014-3176, CVE-2014-3177: A special reward to lokihardt@asrt
  for a combination of bugs in V8, IPC, sync, and extensions that can lead
  to remote code execution outside of the sandbox.

  High CVE-2014-3168: Use-after-free in SVG. Credit to cloudfuzzer. High
  CVE-2014-3169: Use-after-free in DOM. Credit to Andrzej Dyjak. High
  CVE-2014-3170: Extension permission dialog spoofing. Credit to Rob Wu.
  High CVE-2014-3171: Use-after-free in bindings. Credit to cloudfuzzer.
  Medium CVE-2014-3172: Issue related to extension debugging. Credit to Eli
  Grey. Medium CVE-2014-3173: Uninitialized memory read in WebGL. Credit to
  jmuizelaar. Medium CVE-2014-3174: Uninitialized memory read in Web Audio.
  Credit to Atte Kettunen from OUSPG.

  We would also like to thank Collin Payne, Christoph Diehl, Sebastian
  Mauer, Atte Kettunen, and cloudfuzzer for working with us during the
  development cycle to prevent security bugs from ever reaching the stable
  channel. $8000 in additional rewards were issued.

  As usual, our ongoing internal security work responsible for a wide range
  of fixes: CVE-2014-3175: Various fixes from internal audits, fuzzing and
  other initiatives (Chrome 37).

  Many of the above bugs were detected using AddressSanitizer.");
  script_tag(name:"affected", value:"chromium on openSUSE 13.1, openSUSE 12.3");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE12\.3|openSUSE13\.1)");

  script_xref(name:"URL", value:"https://chromium.googlesource.com/chromium/src/+log/36.0.1985.0..37.0.2062.0?pretty=full");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE12.3")
{

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~37.0.2062.94~1.55.3", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~37.0.2062.94~1.55.3", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~37.0.2062.94~1.55.3", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~37.0.2062.94~1.55.3", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~37.0.2062.94~1.55.3", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~37.0.2062.94~1.55.3", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~37.0.2062.94~1.55.3", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~37.0.2062.94~1.55.3", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~37.0.2062.94~1.55.3", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSE13.1")
{

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~37.0.2062.94~50.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~37.0.2062.94~50.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~37.0.2062.94~50.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~37.0.2062.94~50.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~37.0.2062.94~50.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~37.0.2062.94~50.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~37.0.2062.94~50.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~37.0.2062.94~50.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~37.0.2062.94~50.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
