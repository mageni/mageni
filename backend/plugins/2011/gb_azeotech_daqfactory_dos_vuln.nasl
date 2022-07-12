###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_azeotech_daqfactory_dos_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# AzeoTech DAQFactory Denial of Service Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802129");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-05 09:04:20 +0200 (Fri, 05 Aug 2011)");
  script_cve_id("CVE-2011-2956");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("AzeoTech DAQFactory Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICSA-11-122-01.pdf");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw exists due to error in application, which fails to perform
  authentication for certain signals.");
  script_tag(name:"solution", value:"Upgrade to the AzeoTech DAQFactory version 5.85 Build 1842 or later");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is installed with AzeoTech DAQFactory and is prone to
  denial of service vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service (system reboot or shutdown).");
  script_tag(name:"affected", value:"AzeoTech DAQFactory version prior to 5.85 Build 1842");
  script_xref(name:"URL", value:"http://www.azeotech.com/downloads.php");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\DAQFactoryExpress")){
  exit(0);
}

azPath = registry_get_sz(key:"SOFTWARE\DAQFactoryExpress",
                                      item:"Installation Path");
if(azPath != NULL)
{
  azVer = fetch_file_version(sysPath:azPath,
                               file_name:"DAQFactoryExpress.exe");
  if(azVer =! NULL)
  {
    if(version_is_less(version:azVer, test_version:"5.85.1842.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
