###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_2247_1.nasl 14110 2019-03-12 09:28:23Z cfischer $
#
# SuSE Update for flash-player SUSE-SU-2015:2247-1 (flash-player)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851140");
  script_version("$Revision: 14110 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 10:28:23 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-12-11 05:48:26 +0100 (Fri, 11 Dec 2015)");
  script_cve_id("CVE-2015-8045", "CVE-2015-8047", "CVE-2015-8048", "CVE-2015-8049",
                "CVE-2015-8050", "CVE-2015-8055", "CVE-2015-8056", "CVE-2015-8057",
                "CVE-2015-8058", "CVE-2015-8059", "CVE-2015-8060", "CVE-2015-8061",
                "CVE-2015-8062", "CVE-2015-8063", "CVE-2015-8064", "CVE-2015-8065",
                "CVE-2015-8066", "CVE-2015-8067", "CVE-2015-8068", "CVE-2015-8069",
                "CVE-2015-8070", "CVE-2015-8071", "CVE-2015-8401", "CVE-2015-8402",
                "CVE-2015-8403", "CVE-2015-8404", "CVE-2015-8405", "CVE-2015-8406",
                "CVE-2015-8407", "CVE-2015-8408", "CVE-2015-8409", "CVE-2015-8410",
                "CVE-2015-8411", "CVE-2015-8412", "CVE-2015-8413", "CVE-2015-8414",
                "CVE-2015-8415", "CVE-2015-8416", "CVE-2015-8417", "CVE-2015-8418",
                "CVE-2015-8419", "CVE-2015-8420", "CVE-2015-8421", "CVE-2015-8422",
                "CVE-2015-8423", "CVE-2015-8424", "CVE-2015-8425", "CVE-2015-8426",
                "CVE-2015-8427", "CVE-2015-8428", "CVE-2015-8429", "CVE-2015-8430",
                "CVE-2015-8431", "CVE-2015-8432", "CVE-2015-8433", "CVE-2015-8434",
                "CVE-2015-8435", "CVE-2015-8436", "CVE-2015-8437", "CVE-2015-8438",
                "CVE-2015-8439", "CVE-2015-8440", "CVE-2015-8441", "CVE-2015-8442",
                "CVE-2015-8443", "CVE-2015-8444", "CVE-2015-8445", "CVE-2015-8446",
                "CVE-2015-8447", "CVE-2015-8448", "CVE-2015-8449", "CVE-2015-8450",
                "CVE-2015-8451", "CVE-2015-8452", "CVE-2015-8453", "CVE-2015-8454",
                "CVE-2015-8455");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for flash-player SUSE-SU-2015:2247-1 (flash-player)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for flash-player to version 11.2.202.554 fixes the following
  security issues in Adobe security advisory APSB15-32.

  * These updates resolve heap buffer overflow vulnerabilities that could
  lead to code execution (CVE-2015-8438, CVE-2015-8446).

  * These updates resolve memory corruption vulnerabilities that could lead
  to code execution (CVE-2015-8444, CVE-2015-8443, CVE-2015-8417,
  CVE-2015-8416, CVE-2015-8451, CVE-2015-8047, CVE-2015-8455,
  CVE-2015-8045, CVE-2015-8418, CVE-2015-8060, CVE-2015-8419,
  CVE-2015-8408).

  * These updates resolve security bypass vulnerabilities (CVE-2015-8453,
  CVE-2015-8440, CVE-2015-8409).

  * These updates resolve a stack overflow vulnerability that could lead to
  code execution (CVE-2015-8407).

  * These updates resolve a type confusion vulnerability that could lead to
  code execution (CVE-2015-8439).

  * These updates resolve an integer overflow vulnerability that could lead
  to code execution (CVE-2015-8445).

  * These updates resolve a buffer overflow vulnerability that could lead to
  code execution (CVE-2015-8415)

  * These updates resolve use-after-free vulnerabilities that could lead to
  code execution (CVE-2015-8050, CVE-2015-8049, CVE-2015-8437,
  CVE-2015-8450, CVE-2015-8449, CVE-2015-8448, CVE-2015-8436,
  CVE-2015-8452, CVE-2015-8048, CVE-2015-8413, CVE-2015-8412,
  CVE-2015-8410, CVE-2015-8411, CVE-2015-8424, CVE-2015-8422,
  CVE-2015-8420, CVE-2015-8421, CVE-2015-8423, CVE-2015-8425,
  CVE-2015-8433, CVE-2015-8432, CVE-2015-8431, CVE-2015-8426,
  CVE-2015-8430, CVE-2015-8427, CVE-2015-8428, CVE-2015-8429,
  CVE-2015-8434, CVE-2015-8435, CVE-2015-8414, CVE-2015-8454,
  CVE-2015-8059, CVE-2015-8058, CVE-2015-8055, CVE-2015-8057,
  CVE-2015-8056, CVE-2015-8061, CVE-2015-8067, CVE-2015-8066,
  CVE-2015-8062, CVE-2015-8068, CVE-2015-8064, CVE-2015-8065,
  CVE-2015-8063, CVE-2015-8405, CVE-2015-8404, CVE-2015-8402,
  CVE-2015-8403, CVE-2015-8071, CVE-2015-8401, CVE-2015-8406,
  CVE-2015-8069, CVE-2015-8070, CVE-2015-8441, CVE-2015-8442,
  CVE-2015-8447).

  Please also see the referenced vendor advisory.");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-32.html");

  script_tag(name:"affected", value:"flash-player on SUSE Linux Enterprise Desktop 12");
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

  if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~11.2.202.554~114.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"flash-player-gnome", rpm:"flash-player-gnome~11.2.202.554~114.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
