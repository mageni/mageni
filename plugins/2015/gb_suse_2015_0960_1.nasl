###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0960_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for MozillaFirefox SUSE-SU-2015:0960-1 (MozillaFirefox)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850853");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-15 12:19:28 +0200 (Thu, 15 Oct 2015)");
  script_cve_id("CVE-2015-0797", "CVE-2015-2708", "CVE-2015-2709", "CVE-2015-2710",
                "CVE-2015-2713", "CVE-2015-2716");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for MozillaFirefox SUSE-SU-2015:0960-1 (MozillaFirefox)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update to Firefox 31.7.0 ESR (bsc#930622) fixes the following issues:

  * MFSA 2015-46/CVE-2015-2708/CVE-2015-2709 (bmo#1120655, bmo#1143299,
  bmo#1151139, bmo#1152177, bmo#1111251, bmo#1117977, bmo#1128064,
  bmo#1135066, bmo#1143194, bmo#1146101, bmo#1149526, bmo#1153688,
  bmo#1155474) Miscellaneous memory safety hazards (rv:38.0 / rv:31.7)

  * MFSA 2015-47/CVE-2015-0797 (bmo#1080995) Buffer overflow parsing H.264
  video with Linux Gstreamer

  * MFSA 2015-48/CVE-2015-2710 (bmo#1149542) Buffer overflow with SVG
  content and CSS

  * MFSA 2015-51/CVE-2015-2713 (bmo#1153478) Use-after-free during text
  processing with vertical text enabled

  * MFSA 2015-54/CVE-2015-2716 (bmo#1140537) Buffer overflow when parsing
  compressed XML");
  script_tag(name:"affected", value:"MozillaFirefox on SUSE Linux Enterprise Desktop 12");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLED12\.0SP0");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLED12.0SP0")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~31.7.0esr~34.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~31.7.0esr~34.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~31.7.0esr~34.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~31.7.0esr~34.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
