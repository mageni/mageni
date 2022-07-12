###############################################################################
# OpenVAS Vulnerability Test
#
# Becky! Internet Mail Buffer Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.800519");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-02-18 15:32:11 +0100 (Wed, 18 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0569");
  script_bugtraq_id(33756);
  script_name("Becky! Internet Mail Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33892");
  script_xref(name:"URL", value:"http://www.rimarts.jp/downloads/B2/Readme-e.txt");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_becky_internet_mail_detect.nasl");
  script_mandatory_keys("Becky/InternetMail/Ver");
  script_tag(name:"affected", value:"Becky! Internet Mail version 2.48.2 and prior on Windows.");
  script_tag(name:"insight", value:"The flaw is generated when the application fails to perform adequate boundary
  checks on user-supplied input. Boundary error may be generated when the user
  agrees to return a receipt message for a specially crafted e-mail thus
  leading to buffer overflow.");
  script_tag(name:"solution", value:"Update to version 2.50.01 or later.");
  script_tag(name:"summary", value:"This host is running Becky! Internet Mail client which is prone
  to buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to execute arbitrary
  code on the target system and can cause denial-of-service condition.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

bimVer = get_kb_item("Becky/InternetMail/Ver");
if(!bimVer)
  exit(0);

if(version_is_less_equal(version:bimVer, test_version:"2.4.8.2")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
