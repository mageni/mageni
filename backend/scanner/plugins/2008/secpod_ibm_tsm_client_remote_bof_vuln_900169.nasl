##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_tsm_client_remote_bof_vuln_900169.nasl 12602 2018-11-30 14:36:58Z cfischer $
# Description: IBM TSM Client Remote Heap BOF Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.900169");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-11-05 06:52:23 +0100 (Wed, 05 Nov 2008)");
  script_cve_id("CVE-2008-4801");
  script_bugtraq_id(31988);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Buffer overflow");
  script_name("IBM TSM Client Remote Heap BOF Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32465/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-071/");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21322623");

  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow execution of arbitrary code or cause
  denial of service.");

  script_tag(name:"affected", value:"- IBM Tivoli Storage Manager (TSM) versions 5.5.0.0 through 5.5.0.7

  - IBM Tivoli Storage Manager (TSM) versions 5.4.0.0 through 5.4.2.2

  - IBM Tivoli Storage Manager (TSM) versions 5.3.0.0 through 5.3.6.1

  - IBM Tivoli Storage Manager (TSM) versions 5.2.0.0 through 5.2.5.2

  - IBM Tivoli Storage Manager (TSM) versions 5.1.0.0 through 5.1.8.1

  - IBM Tivoli Storage Manager (TSM) Express all levels");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"summary", value:"This host is installed with IBM TSM Client and is prone to heap
  based buffer overflow vulnerability.");

  script_tag(name:"insight", value:"Vulnerability exists due to an input validation error in TSM Backup-Archive
  client, which affects the Client Acceptor Daemon (CAD) and the Backup-Archive client scheduler and scheduler
  service when the option 'SCHEDMODE' is set to 'PROMPTED'.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\IBM\ADSM\CurrentVersion\Api";
pkgName = registry_get_sz(key:key, item:"Path");

if("Tivoli\TSM" >!< pkgName){
  exit(0);
}

tsmVer = registry_get_sz(key:key, item:"PtfLevel");
if(tsmVer){
  if(egrep(pattern:"^(5\.(1\.([0-7]\..*|8\.[01])|2\.([0-4]\..*|5\.[0-2])|3\." +
                   "([0-5]\..*|6\.[01])|4\.([01]\..*|2\.[0-2])|5\.(0\.[0-7])))$",
           string:tsmVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
