###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0192_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for seamonkey openSUSE-SU-2015:0192-1 (seamonkey)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850632");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-02-03 05:45:00 +0100 (Tue, 03 Feb 2015)");
  script_cve_id("CVE-2014-8634", "CVE-2014-8635", "CVE-2014-8636", "CVE-2014-8637", "CVE-2014-8638", "CVE-2014-8639", "CVE-2014-8640", "CVE-2014-8641", "CVE-2014-8642", "CVE-2014-8643");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("SuSE Update for seamonkey openSUSE-SU-2015:0192-1 (seamonkey)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'seamonkey'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla seamonkey was updated to SeaMonkey 2.32 (bnc#910669)

  * MFSA 2015-01/CVE-2014-8634/CVE-2014-8635 Miscellaneous memory safety
  hazards

  * MFSA 2015-02/CVE-2014-8637 (bmo#1094536) Uninitialized memory use
  during bitmap rendering

  * MFSA 2015-03/CVE-2014-8638 (bmo#1080987) sendBeacon requests lack an
  Origin header

  * MFSA 2015-04/CVE-2014-8639 (bmo#1095859) Cookie injection through
  Proxy Authenticate responses

  * MFSA 2015-05/CVE-2014-8640 (bmo#1100409) Read of uninitialized memory
  in Web Audio

  * MFSA 2015-06/CVE-2014-8641 (bmo#1108455) Read-after-free in WebRTC

  * MFSA 2015-07/CVE-2014-8643 (bmo#1114170) (Windows-only) Gecko Media
  Plugin sandbox escape

  * MFSA 2015-08/CVE-2014-8642 (bmo#1079658) Delegated OCSP responder
  certificates failure with id-pkix-ocsp-nocheck extension

  * MFSA 2015-09/CVE-2014-8636 (bmo#987794) XrayWrapper bypass through DOM
  objects

  - use GStreamer 1.0 from 13.2 on");
  script_tag(name:"affected", value:"seamonkey on openSUSE 13.1");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
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

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.32~44.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-debuginfo", rpm:"seamonkey-debuginfo~2.32~44.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-debugsource", rpm:"seamonkey-debugsource~2.32~44.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.32~44.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.32~44.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-translations-common", rpm:"seamonkey-translations-common~2.32~44.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-translations-other", rpm:"seamonkey-translations-other~2.32~44.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}