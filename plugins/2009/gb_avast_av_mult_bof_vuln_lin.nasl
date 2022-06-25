###############################################################################
# OpenVAS Vulnerability Test
#
# avast! AntiVirus Multiple BOF Vulnerabilities (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800599");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-07-09 10:58:23 +0200 (Thu, 09 Jul 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-6846");
  script_bugtraq_id(32747);
  script_name("avast! AntiVirus Multiple BOF Vulnerabilities (Linux)");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/47251");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/382096.php");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2008/3460");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_avast_av_detect_lin.nasl");
  script_mandatory_keys("Avast!/AV/Linux/Ver");
  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code in the context
  of affected application, and can cause denial of service.");
  script_tag(name:"affected", value:"avast! Linux Home Edition 1.0.8-2 and prior on Linux");
  script_tag(name:"insight", value:"Multiple buffer overflow errors occur while processing malformed ISO or
  RPM files as the application fails to perform adequate bounds check on
  files before copying them into an insufficiently sized buffer.");
  script_tag(name:"solution", value:"Upgrade to avast! Linux Home Edition latest version.");
  script_tag(name:"summary", value:"The host is installed with avast! AntiVirus and is prone to
  multiple Buffer Overflow Vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

avastVer = get_kb_item("Avast!/AV/Linux/Ver");
if(!avastVer)
  exit(0);

if(version_is_less_equal(version:avastVer, test_version:"1.0.8")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
