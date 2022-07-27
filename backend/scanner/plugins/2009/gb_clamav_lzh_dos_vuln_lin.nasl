###############################################################################
# OpenVAS Vulnerability Test
#
# ClamAV LZH File Unpacking Denial of Service Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.800597");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-6845");
  script_bugtraq_id(32752);
  script_name("ClamAV LZH File Unpacking Denial of Service Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://www.ivizsecurity.com/security-advisory-iviz-sr-08011.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_detect_lin.nasl");
  script_mandatory_keys("ClamAV/Lin/Ver");
  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code in the context
  of affected application, and can cause denial of service.");
  script_tag(name:"affected", value:"ClamAV 0.93.3 and prior on Linux.");
  script_tag(name:"insight", value:"A segmentation fault ocurs in the unpack feature, while processing malicious
  LZH file.");
  script_tag(name:"solution", value:"Upgrade to ClamAV 0.94 or later.");
  script_tag(name:"summary", value:"The host is installed with ClamAV and is prone to Denial of Service
  Vulnerability.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

clamavVer = get_kb_item("ClamAV/Lin/Ver");
if(!clamavVer)
  exit(0);

if(version_is_less_equal(version:clamavVer, test_version:"0.93.3")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
