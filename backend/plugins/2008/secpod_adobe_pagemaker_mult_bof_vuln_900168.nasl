##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_pagemaker_mult_bof_vuln_900168.nasl 12602 2018-11-30 14:36:58Z cfischer $
# Description: Adobe PageMaker Font Structure Multiple BOF Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900168");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-10-31 14:50:32 +0100 (Fri, 31 Oct 2008)");
  script_bugtraq_id(31975);
  script_cve_id("CVE-2007-6432", "CVE-2007-5394", "CVE-2007-6021");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Buffer overflow");
  script_name("Adobe PageMaker Font Structure Multiple BOF Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/27200/");
  script_xref(name:"URL", value:"http://www.securitytracker.com/alerts/2008/Oct/1021119.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa08-10.html");

  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Allows remote attackers to execute arbitrary code, and deny the service.");

  script_tag(name:"affected", value:"Adobe PageMaker versions 7.0.2 and prior on Windows (all)");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"summary", value:"This host is installed with Adobe PageMaker and is prone to multiple
  buffer overflow vulnerability.");

  script_tag(name:"insight", value:"The flaws are due to error in processing specially crafted PMD files.
  These can be exploited to cause stack-based and heap-based overflow.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Adobe PageMaker 7.0";
pmVer = registry_get_sz(key:key, item:"DisplayVersion");

if(pmVer){
  if(egrep(pattern:"^([0-6](\..*)|7\.0(\.[0-2])?)$", string:pmVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
