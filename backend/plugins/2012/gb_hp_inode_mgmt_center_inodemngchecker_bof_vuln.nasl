###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_inode_mgmt_center_inodemngchecker_bof_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# HP iNode Management Center iNodeMngChecker.exe Multiple Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:hp:inode_management_center_pc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802673");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-3254");
  script_bugtraq_id(55160);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-09-20 13:36:31 +0530 (Thu, 20 Sep 2012)");
  script_name("HP iNode Management Center iNodeMngChecker.exe Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50350/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/523984");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-12-163/");
  script_xref(name:"URL", value:"http://telussecuritylabs.com/threats/show/TSL20120822-08");
  script_xref(name:"URL", value:"http://h20565.www2.hp.com/portal/site/hpsc/public/kb/docDisplay/?docId=emr_na-c03473527");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_inode_mgmt_center_detect.nasl");
  script_mandatory_keys("HP/iMC/Version", "HP/iMC/Path");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  under the context of the SYSTEM user which results in stack-based buffer
  overflow.");
  script_tag(name:"affected", value:"HP iNode Management Center iNode PC 5.1 E0303 and prior");
  script_tag(name:"insight", value:"The flaws are present due to error in the iNOdeMngChecker.exe component which
  fails to handle the user supplied crafted 0x0A0BF007 packet.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"summary", value:"This host is installed with HP iNode Management Center and is prone
  to multiple vulnerabilities.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://h20566.www2.hp.com/portal/site/hpsc/public/kb/docDisplay/?docId=emr_na-c03473527");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

imcPath = get_kb_item("HP/iMC/Path");

if(imcPath && "Could not find the install Location" >!< imcPath)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:imcPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:imcPath);

  if(get_file_size(share:share, file:file + "\\iNodeMngChecker.exe"))
  {
    imcVer = get_app_version(cpe:CPE);

    if(imcVer &&
       version_in_range(version:imcVer, test_version:"5.00", test_version2:"5.10.0303"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

