###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Exchange Server Privilege Escalation Vulnerability (3040856)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:microsoft:exchange_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805146");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2015-1628", "CVE-2015-1629", "CVE-2015-1630", "CVE-2015-1631",
                "CVE-2015-1632");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-03-11 11:38:48 +0530 (Wed, 11 Mar 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Exchange Server Privilege Escalation Vulnerability (3040856)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-026.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to an improper
  validation of user supplied input before returning it to users,

  - /owa/ script to the 'X-OWA-Canary' cookie value, when 'ae' is set to
    'Item' and 't' is set to 'AD.RecipientType.User'.

  - errorfe.aspx script to the 'msgParam' parameter.

  - when handling server audit reports and other inputs.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"Microsoft Exchange Server 2013 Service Pack 1

  Microsoft Exchange Server 2013 Cumulative Update 7");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3040856");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-026");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_exchange_server_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Exchange/Server/Ver");
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

exchangePath = get_app_location(cpe:CPE);
if(!exchangePath || "Could not find the install location" >< exchangePath){
  exit(0);
}

exeVer = fetch_file_version(sysPath:exchangePath, file_name:"Bin\ExSetup.exe");
if(!exeVer){
  exit(0);
}

if(version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.847.37"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

if(get_kb_item("MS/Exchange/Cumulative/Update"))
{
  if(version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.1044.28"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
