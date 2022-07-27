###############################################################################
# OpenVAS Vulnerability Test
# $Id: mgasa-2016-0116.nasl 14180 2019-03-14 12:29:16Z cfischer $
#
# Mageia Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.com>
#
# Copyright:
# Copyright (c) 2016 Eero Volotinen, http://www.solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131282");
  script_version("$Revision: 14180 $");
  script_tag(name:"creation_date", value:"2016-03-31 08:05:06 +0300 (Thu, 31 Mar 2016)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:29:16 +0100 (Thu, 14 Mar 2019) $");
  script_name("Mageia Linux Local Check: mgasa-2016-0116");
  script_tag(name:"insight", value:"The webkit2 package has been updated to version 2.10.9, fixing several security issues and other bugs.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0116.html");
  script_cve_id("CVE-2015-1068", "CVE-2015-1069", "CVE-2015-1070", "CVE-2015-1071", "CVE-2015-1072", "CVE-2015-1073", "CVE-2015-1075", "CVE-2015-1076", "CVE-2015-1077", "CVE-2015-1081", "CVE-2015-1082", "CVE-2015-1119", "CVE-2015-1120", "CVE-2015-1121", "CVE-2015-1122", "CVE-2015-1124", "CVE-2015-1126", "CVE-2015-1127", "CVE-2015-1152", "CVE-2015-1153", "CVE-2015-1154", "CVE-2015-1155", "CVE-2015-1156", "CVE-2015-3658", "CVE-2015-3659", "CVE-2015-3660", "CVE-2015-3727", "CVE-2015-3730", "CVE-2015-3731", "CVE-2015-3732", "CVE-2015-3733", "CVE-2015-3734", "CVE-2015-3735", "CVE-2015-3736", "CVE-2015-3737", "CVE-2015-3738", "CVE-2015-3739", "CVE-2015-3740", "CVE-2015-3741", "CVE-2015-3742", "CVE-2015-3743", "CVE-2015-3744", "CVE-2015-3745", "CVE-2015-3746", "CVE-2015-3747", "CVE-2015-3748", "CVE-2015-3749", "CVE-2015-3750", "CVE-2015-3751", "CVE-2015-3752", "CVE-2015-3753", "CVE-2015-3754", "CVE-2015-3755", "CVE-2015-5788", "CVE-2015-5793", "CVE-2015-5794", "CVE-2015-5795", "CVE-2015-5797", "CVE-2015-5799", "CVE-2015-5800", "CVE-2015-5801", "CVE-2015-5803", "CVE-2015-5804", "CVE-2015-5805", "CVE-2015-5806", "CVE-2015-5807", "CVE-2015-5809", "CVE-2015-5810", "CVE-2015-5811", "CVE-2015-5812", "CVE-2015-5813", "CVE-2015-5814", "CVE-2015-5815", "CVE-2015-5816", "CVE-2015-5817", "CVE-2015-5818", "CVE-2015-5819", "CVE-2015-5822", "CVE-2015-5823", "CVE-2015-5825", "CVE-2015-5827", "CVE-2015-5828", "CVE-2015-5928", "CVE-2015-5929", "CVE-2015-5930", "CVE-2015-5931", "CVE-2015-7002", "CVE-2015-7012", "CVE-2015-7013", "CVE-2015-7014", "CVE-2015-7048", "CVE-2015-7095", "CVE-2015-7096", "CVE-2015-7097", "CVE-2015-7098", "CVE-2015-7099", "CVE-2015-7100", "CVE-2015-7102", "CVE-2015-7103", "CVE-2015-7104", "CVE-2016-1723", "CVE-2016-1724", "CVE-2016-1725", "CVE-2016-1726", "CVE-2016-1727", "CVE-2016-1728");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Mageia Linux Local Security Checks mgasa-2016-0116");
  script_copyright("Eero Volotinen");
  script_family("Mageia Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MAGEIA5")
{
if ((res = isrpmvuln(pkg:"webkit2", rpm:"webkit2~2.10.9~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99);
  exit(0);
}
