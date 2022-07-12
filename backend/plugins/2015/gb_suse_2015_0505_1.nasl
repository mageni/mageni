###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0505_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for Security openSUSE-SU-2015:0505-1 (Security)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850643");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-03-17 06:39:10 +0100 (Tue, 17 Mar 2015)");
  script_cve_id("CVE-2015-1212", "CVE-2015-1213", "CVE-2015-1214", "CVE-2015-1215", "CVE-2015-1216", "CVE-2015-1217", "CVE-2015-1218", "CVE-2015-1219", "CVE-2015-1220", "CVE-2015-1221", "CVE-2015-1222", "CVE-2015-1223", "CVE-2015-1224", "CVE-2015-1225", "CVE-2015-1226", "CVE-2015-1227", "CVE-2015-1228", "CVE-2015-1229", "CVE-2015-1230", "CVE-2015-1231");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for Security openSUSE-SU-2015:0505-1 (Security)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Security'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Chromium was updated to 41.0.2272.76 (bnc#920825)

  Security fixes:

  * CVE-2015-1212: Out-of-bounds write in media

  * CVE-2015-1213: Out-of-bounds write in skia filters

  * CVE-2015-1214: Out-of-bounds write in skia filters

  * CVE-2015-1215: Out-of-bounds write in skia filters

  * CVE-2015-1216: Use-after-free in v8 bindings

  * CVE-2015-1217: Type confusion in v8 bindings

  * CVE-2015-1218: Use-after-free in dom

  * CVE-2015-1219: Integer overflow in webgl

  * CVE-2015-1220: Use-after-free in gif decoder

  * CVE-2015-1221: Use-after-free in web databases

  * CVE-2015-1222: Use-after-free in service workers

  * CVE-2015-1223: Use-after-free in dom

  * CVE-2015-1230: Type confusion in v8

  * CVE-2015-1224: Out-of-bounds read in vpxdecoder

  * CVE-2015-1225: Out-of-bounds read in pdfium

  * CVE-2015-1226: Validation issue in debugger

  * CVE-2015-1227: Uninitialized value in blink

  * CVE-2015-1228: Uninitialized value in rendering

  * CVE-2015-1229: Cookie injection via proxies

  * CVE-2015-1231: Various fixes from internal audits

  * Multiple vulnerabilities in V8 fixed at the tip of the 4.1 branch");
  script_tag(name:"affected", value:"Security on openSUSE 13.1");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.1")
{

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~41.0.2272.76~72.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~41.0.2272.76~72.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~41.0.2272.76~72.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~41.0.2272.76~72.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~41.0.2272.76~72.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~41.0.2272.76~72.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~41.0.2272.76~72.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~41.0.2272.76~72.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~41.0.2272.76~72.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}