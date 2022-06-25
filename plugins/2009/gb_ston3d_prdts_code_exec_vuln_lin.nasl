###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ston3d_prdts_code_exec_vuln_lin.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# StoneTrip Ston3D Standalone Player Code Execution Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.800576");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1792");
  script_bugtraq_id(35105);
  script_name("StoneTrip Ston3D Standalone Player Code Execution Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/StoneTrip-S3DPlayers");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/503887/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ston3d_prdts_detect_lin.nasl");
  script_mandatory_keys("Ston3D/Standalone/Player/Lin/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary
codes in the context of the application via shell metacharacters in the 'sURL'
argument.");
  script_tag(name:"affected", value:"StoneTrip Ston3D Standalone Player version 1.6.2.4 and prior.");
  script_tag(name:"insight", value:"The flaw is generated due to inadequate sanitation of user
supplied data used in the 'system.openURL()' function.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with StoneTrip Ston3D Standalone Player
and is prone to Code Execution vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");
  exit(0);
}


include("version_func.inc");

sapVer = get_kb_item("Ston3D/Standalone/Player/Lin/Ver");
if(!sapVer){
  exit(0);
}

if(version_is_less_equal(version:sapVer, test_version:"1.6.2.4")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
