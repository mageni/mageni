###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_domain_policy_bypass_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Microsoft Internet Explorer Domain Policy Bypass Vulnerability
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803302");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2012-6502");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-02-01 11:11:56 +0530 (Fri, 01 Feb 2013)");
  script_name("Microsoft Internet Explorer Domain Policy Bypass Vulnerability");
  script_xref(name:"URL", value:"http://www.nsfocus.com/en/2012/advisories_1228/119.html");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2012-6502");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to disclosure the information
  when a user views a specially crafted webpage.");
  script_tag(name:"affected", value:"Microsoft Internet Explorer version 6.x/7.x/8.x/9.x on Windows XP and 2003");
  script_tag(name:"insight", value:"The flaw due to error in UNC share pathname in SRC attribute of a SCRIPT
  element, which allows attackers to obtain sensitive information about the
  existence of files and read certain data from files.");
  script_tag(name:"solution", value:"Upgrade to Internet Explorer 10.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with Microsoft Internet Explorer and is
  prone to domain policy bypass vulnerability.");

  script_xref(name:"URL", value:"http://ie.microsoft.com/testdrive/info/downloads");
  exit(0);
}

include("secpod_reg.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(hotfix_check_sp(xp:4, win2003:3) > 0 )
{
  if(ieVer =~ "^(6|7|8|9)"){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
