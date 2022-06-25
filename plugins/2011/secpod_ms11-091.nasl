###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Publisher Remote Code Execution Vulnerabilities (2607702)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902493");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2011-1508", "CVE-2011-3410", "CVE-2011-3411", "CVE-2011-3412");
  script_bugtraq_id(50090, 50943, 50949, 50955);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-12-14 09:22:08 +0530 (Wed, 14 Dec 2011)");
  script_name("Microsoft Publisher Remote Code Execution Vulnerabilities (2607702)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Publisher/Version");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553084");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2596705");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-091/");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute arbitrary code on
  the remote system.");
  script_tag(name:"affected", value:"Microsoft Publisher 2003 Service Pack 3 and prior
  Microsoft Publisher 2007 Service Pack 3 and prior");
  script_tag(name:"insight", value:"The flaw is due to the way Microsoft Publisher parses specially
  crafted Publisher files, which could allow attackers to execute arbitrary
  code by tricking a user into opening a specially crafted Publisher file.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS11-091.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

pubVer = get_kb_item( "SMB/Office/Publisher/Version" );
if( isnull( pubVer ) ) exit( 0 );

if( version_in_range( version:pubVer, test_version:"11.0", test_version2:"11.0.8341" ) ||
    version_in_range( version:pubVer, test_version:"12.0", test_version2:"12.0.6652.4999" ) ){
  report = report_fixed_ver( installed_version:pubVer, fixed_version:"11.0.8341/12.0.6652.4999" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );